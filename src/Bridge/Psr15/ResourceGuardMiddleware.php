<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Psr15;

use GuillaumeTissier\ResourceGuard\Guard\AuthenticationFailed;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware (Slim, Mezzio...). On success the Principal is available
 * as the request attribute self::PRINCIPAL_ATTRIBUTE.
 */
final readonly class ResourceGuardMiddleware implements MiddlewareInterface
{
    public const PRINCIPAL_ATTRIBUTE = 'oauth_principal';

    public function __construct(
        private ResourceGuard $guard,
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $uri = $request->getUri()->withQuery('')->withFragment('');

        try {
            $principal = $this->guard->authenticate(
                $request->getMethod(),
                (string) $uri,
                $request->getHeaderLine('Authorization') ?: null,
                $request->getHeader('DPoP'),
            );
        } catch (AuthenticationFailed $e) {
            $response = $this->responseFactory->createResponse($e->statusCode)
                ->withBody($this->streamFactory->createStream((string) json_encode($e->toArray())));
            foreach ($e->responseHeaders() as $name => $value) {
                $response = $response->withHeader($name, $value);
            }

            return $response;
        }

        return $handler->handle($request->withAttribute(self::PRINCIPAL_ATTRIBUTE, $principal));
    }
}
