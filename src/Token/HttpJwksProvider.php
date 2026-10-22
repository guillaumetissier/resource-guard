<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

use Jose\Component\Core\JWKSet;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Fetches the auth server's /.well-known/jwks.json and caches it.
 */
final class HttpJwksProvider implements JwksProviderInterface
{
    private ?JWKSet $memo = null;
    private int $lastForcedRefresh = 0;

    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly ?CacheInterface $cache = null,
        private readonly int $cacheTtl = 3600,
        // Forced refreshes are triggered by unknown signatures: rate-limit them so forged
        // tokens cannot be used to hammer the auth server.
        private readonly int $minSecondsBetweenForcedRefresh = 60,
    ) {
    }

    public function getKeySet(bool $forceRefresh = false): JWKSet
    {
        if ($forceRefresh && time() - $this->lastForcedRefresh < $this->minSecondsBetweenForcedRefresh) {
            $forceRefresh = false;
        }

        if (!$forceRefresh) {
            if (null !== $this->memo) {
                return $this->memo;
            }
            $cached = $this->cache?->get($this->cacheKey());
            if (\is_string($cached)) {
                return $this->memo = JWKSet::createFromJson($cached);
            }
        } else {
            $this->lastForcedRefresh = time();
        }

        $response = $this->httpClient->sendRequest($this->requestFactory->createRequest('GET', $this->jwksUri));
        if (200 !== $response->getStatusCode()) {
            throw new \RuntimeException(\sprintf('Unable to fetch JWKS from %s (HTTP %d)', $this->jwksUri, $response->getStatusCode()));
        }

        $json = (string) $response->getBody();
        $keySet = JWKSet::createFromJson($json);
        $this->cache?->set($this->cacheKey(), $json, $this->cacheTtl);

        return $this->memo = $keySet;
    }

    private function cacheKey(): string
    {
        return 'resource_guard_jwks_'.hash('sha256', $this->jwksUri);
    }
}
