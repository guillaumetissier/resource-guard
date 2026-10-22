<?php

declare(strict_types=1);

/*
 * Demo resource server protected by resource-guard, for functional tests:
 *   php -S 127.0.0.1:8000 tools/demo-api.php
 *
 * Wired like a real deployment: JWKS fetched over HTTP from the issuer (tools/issuer.php) and
 * cached, DPoP replay store and webhook de-duplication in a cache shared by all PHP processes,
 * authentication through the PSR-15 middleware.
 *
 *   GET  /health
 *   GET  /api/whoami                             who is calling (any valid token)
 *   GET  /api/vehicles?domain=/a1/a10/           needs vehicle:r on that domain
 *   POST /api/vehicles?domain=/a1/a10/           needs vehicle:w and the scope "vehicles.write"
 *   PUT  /api/profiles/{owner}?domain=/a1/a10/   needs user:w, or user:w:own when {owner} is the caller
 *   POST /webhook                                signed auth server event
 */

use GuillaumeTissier\ResourceGuard\Access\AccessLevel;
use GuillaumeTissier\ResourceGuard\Bridge\Psr15\ResourceGuardMiddleware;
use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use GuillaumeTissier\ResourceGuard\Dpop\Psr16ReplayStore;
use GuillaumeTissier\ResourceGuard\Guard\Principal;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use GuillaumeTissier\ResourceGuard\Token\AccessTokenValidator;
use GuillaumeTissier\ResourceGuard\Token\HttpJwksProvider;
use GuillaumeTissier\ResourceGuard\Tools\CurlClient;
use GuillaumeTissier\ResourceGuard\Tools\FileCache;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookEvent;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookSignature;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function GuillaumeTissier\ResourceGuard\Tools\readJson;
use function GuillaumeTissier\ResourceGuard\Tools\state;

require __DIR__.'/bootstrap.php';

$config = readJson('config.json');
if ([] === $config) {
    http_response_code(503);
    echo '{"error":"run php tools/rg-cli.php init first"}';

    return;
}

$factory = new Psr17Factory();
$cache = new FileCache(state('cache'));

$json = static fn (int $status, array $data): ResponseInterface => $factory->createResponse($status)
    ->withHeader('Content-Type', 'application/json')
    ->withBody($factory->createStream((string) json_encode($data, \JSON_UNESCAPED_SLASHES)));

// PSR-7 request from the PHP globals.
$request = $factory->createServerRequest($_SERVER['REQUEST_METHOD'] ?? 'GET', 'http://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['REQUEST_URI'] ?? '/'), $_SERVER);
foreach (getallheaders() as $name => $value) {
    $request = $request->withAddedHeader($name, $value);
}
$request = $request->withBody($factory->createStream((string) file_get_contents('php://input')));
parse_str((string) $request->getUri()->getQuery(), $query);
$request = $request->withQueryParams($query);

$path = $request->getUri()->getPath();

$response = match (true) {
    '/health' === $path => $json(200, ['status' => 'ok']),
    '/webhook' === $path && 'POST' === $request->getMethod() => (static function () use ($request, $config, $cache, $json): ResponseInterface {
        $body = (string) $request->getBody();
        if (!(new WebhookSignature($config['webhook_secret']))->verify($body, $request->getHeaderLine(WebhookSignature::HEADER) ?: null)) {
            return $json(400, ['error' => 'invalid_signature']);
        }
        $event = WebhookEvent::fromJson($body);
        if ($cache->has('webhook_'.$event->id)) {
            return $json(200, ['status' => 'duplicate', 'id' => $event->id]);
        }
        $cache->set('webhook_'.$event->id, true, 86400);

        return $json(202, ['status' => 'accepted', 'type' => $event->type, 'user_id' => $event->userId()]);
    })(),
    str_starts_with($path, '/api/') => (static function () use ($request, $config, $cache, $factory, $json): ResponseInterface {
        $guard = new ResourceGuard(
            new AccessTokenValidator(
                new HttpJwksProvider($config['issuer'].'/.well-known/jwks.json', new CurlClient(), $factory, $cache),
                $config['allowed_clients'],
            ),
            new DpopProofValidator(new Psr16ReplayStore($cache)),
            requireDpop: $config['require_dpop'],
        );
        $handler = new class($json) implements RequestHandlerInterface {
            public function __construct(private Closure $json)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                /** @var Principal $principal */
                $principal = $request->getAttribute(ResourceGuardMiddleware::PRINCIPAL_ATTRIBUTE);
                $path = $request->getUri()->getPath();
                $domain = (string) ($request->getQueryParams()['domain'] ?? '/');
                $forbidden = fn (string $why): ResponseInterface => ($this->json)(403, ['error' => 'forbidden', 'error_description' => $why]);

                if ('/api/whoami' === $path) {
                    return ($this->json)(200, [
                        'user_id' => $principal->userId,
                        'client_id' => $principal->clientId,
                        'scopes' => $principal->scopes,
                        'dpop' => $principal->proofOfPossession,
                        'impersonated_by' => $principal->actorId(),
                        'read_only' => $principal->isReadOnly(),
                        'domain' => $principal->domain(),
                    ]);
                }
                if ('/api/vehicles' === $path && 'GET' === $request->getMethod()) {
                    return $principal->can('vehicle', AccessLevel::Read, $domain)
                        ? ($this->json)(200, ['vehicles' => [], 'domain' => $domain, 'level' => $principal->accessLevel('vehicle', $domain)->label()])
                        : $forbidden('vehicle:r needed on '.$domain);
                }
                if ('/api/vehicles' === $path && 'POST' === $request->getMethod()) {
                    if (!$principal->hasScope('vehicles.write')) {
                        return ($this->json)(403, ['error' => 'insufficient_scope', 'error_description' => 'scope vehicles.write needed']);
                    }

                    return $principal->can('vehicle', AccessLevel::Write, $domain)
                        ? ($this->json)(201, ['created' => true, 'domain' => $domain, 'by' => $principal->userId, 'on_behalf_of' => $principal->actorId()])
                        : $forbidden('vehicle:w needed on '.$domain);
                }
                if (1 === preg_match('#^/api/profiles/([^/]+)$#', $path, $m) && 'PUT' === $request->getMethod()) {
                    return $principal->can('user', AccessLevel::Write, $domain, ownerId: $m[1])
                        ? ($this->json)(200, ['updated' => $m[1]])
                        : $forbidden('user:w (or user:w:own on one\'s own profile) needed on '.$domain);
                }

                return ($this->json)(404, ['error' => 'not_found']);
            }
        };

        return (new ResourceGuardMiddleware($guard, $factory, $factory))->process($request, $handler);
    })(),
    default => $json(404, ['error' => 'not_found']),
};

foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header($name.': '.$value, false);
    }
}
// After the headers: PHP switches to 401 when a WWW-Authenticate header is sent.
http_response_code($response->getStatusCode());
echo $response->getBody();
