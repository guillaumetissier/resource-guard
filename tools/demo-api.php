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
use function GuillaumeTissier\ResourceGuard\Tools\str;

require __DIR__.'/bootstrap.php';

/**
 * Routes of /api/*, behind the resource-guard PSR-15 middleware.
 */
final readonly class DemoApi implements RequestHandlerInterface
{
    public function __construct(private Psr17Factory $factory)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $principal = $request->getAttribute(ResourceGuardMiddleware::PRINCIPAL_ATTRIBUTE);
        if (!$principal instanceof Principal) {
            return $this->json(500, ['error' => 'no principal: the middleware did not run']);
        }
        $path = $request->getUri()->getPath();
        $domain = str($request->getQueryParams(), 'domain') ?: '/';

        if ('/api/whoami' === $path) {
            return $this->json(200, [
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
                ? $this->json(200, ['vehicles' => [], 'domain' => $domain, 'level' => $principal->accessLevel('vehicle', $domain)->label()])
                : $this->forbidden('vehicle:r needed on '.$domain);
        }
        if ('/api/vehicles' === $path && 'POST' === $request->getMethod()) {
            if (!$principal->hasScope('vehicles.write')) {
                return $this->json(403, ['error' => 'insufficient_scope', 'error_description' => 'scope vehicles.write needed']);
            }

            return $principal->can('vehicle', AccessLevel::Write, $domain)
                ? $this->json(201, ['created' => true, 'domain' => $domain, 'by' => $principal->userId, 'on_behalf_of' => $principal->actorId()])
                : $this->forbidden('vehicle:w needed on '.$domain);
        }
        if (1 === preg_match('#^/api/profiles/([^/]+)$#', $path, $m) && 'PUT' === $request->getMethod()) {
            return $principal->can('user', AccessLevel::Write, $domain, ownerId: $m[1])
                ? $this->json(200, ['updated' => $m[1]])
                : $this->forbidden('user:w (or user:w:own on one\'s own profile) needed on '.$domain);
        }

        return $this->json(404, ['error' => 'not_found']);
    }

    /**
     * @param array<string, mixed> $data
     */
    public function json(int $status, array $data): ResponseInterface
    {
        return $this->factory->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->factory->createStream((string) json_encode($data, \JSON_UNESCAPED_SLASHES)));
    }

    private function forbidden(string $why): ResponseInterface
    {
        return $this->json(403, ['error' => 'forbidden', 'error_description' => $why]);
    }
}

$config = readJson('config.json');
if ([] === $config) {
    http_response_code(503);
    echo '{"error":"run php tools/rg-cli.php init first"}';

    return;
}

$factory = new Psr17Factory();
$cache = new FileCache(state('cache'));
$api = new DemoApi($factory);

// PSR-7 request from the PHP globals.
$request = $factory->createServerRequest(str($_SERVER, 'REQUEST_METHOD') ?: 'GET', 'http://'.(str($_SERVER, 'HTTP_HOST') ?: 'localhost').(str($_SERVER, 'REQUEST_URI') ?: '/'), $_SERVER);
$headers = getallheaders();
foreach (is_array($headers) ? $headers : [] as $name => $value) {
    if (is_string($name) && is_string($value)) {
        $request = $request->withAddedHeader($name, $value);
    }
}
$request = $request->withBody($factory->createStream((string) file_get_contents('php://input')));
parse_str($request->getUri()->getQuery(), $query);
$request = $request->withQueryParams($query);

$path = $request->getUri()->getPath();

if ('/health' === $path) {
    $response = $api->json(200, ['status' => 'ok']);
} elseif ('/webhook' === $path && 'POST' === $request->getMethod()) {
    $body = (string) $request->getBody();
    if (!(new WebhookSignature(str($config, 'webhook_secret')))->verify($body, $request->getHeaderLine(WebhookSignature::HEADER) ?: null)) {
        $response = $api->json(400, ['error' => 'invalid_signature']);
    } else {
        $event = WebhookEvent::fromJson($body);
        if ($cache->has('webhook_'.$event->id)) {
            $response = $api->json(200, ['status' => 'duplicate', 'id' => $event->id]);
        } else {
            $cache->set('webhook_'.$event->id, true, 86400);
            $response = $api->json(202, ['status' => 'accepted', 'type' => $event->type, 'user_id' => $event->userId()]);
        }
    }
} elseif (str_starts_with($path, '/api/')) {
    $allowedClients = is_array($config['allowed_clients'] ?? null) ? array_values(array_filter($config['allowed_clients'], is_string(...))) : [];
    $guard = new ResourceGuard(
        new AccessTokenValidator(
            new HttpJwksProvider(str($config, 'issuer').'/.well-known/jwks.json', new CurlClient(), $factory, $cache),
            $allowedClients,
        ),
        new DpopProofValidator(new Psr16ReplayStore($cache)),
        requireDpop: false !== ($config['require_dpop'] ?? true),
    );
    $response = (new ResourceGuardMiddleware($guard, $factory, $factory))->process($request, $api);
} else {
    $response = $api->json(404, ['error' => 'not_found']);
}

foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header($name.': '.$value, false);
    }
}
// After the headers: PHP switches to 401 when a WWW-Authenticate header is sent.
http_response_code($response->getStatusCode());
echo $response->getBody();
