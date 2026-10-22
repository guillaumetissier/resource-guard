<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Dpop;

use Psr\SimpleCache\CacheInterface;

/**
 * Replay store backed by any PSR-16 cache (Laravel's cache repository, Symfony's Psr16Cache...).
 *
 * PSR-16 has no atomic "add if absent", so two concurrent requests carrying the same proof
 * could both pass in a very narrow window. Use an atomic store (e.g. Redis SET NX) when
 * that matters for your threat model.
 */
final readonly class Psr16ReplayStore implements ReplayStoreInterface
{
    public function __construct(
        private CacheInterface $cache,
        private string $prefix = 'dpop_jti_',
    ) {
    }

    public function remember(string $key, \DateTimeImmutable $expiresAt): bool
    {
        // PSR-16 keys may not contain {}()/\@: - hash to stay within the allowed charset.
        $cacheKey = $this->prefix.hash('sha256', $key);

        if ($this->cache->has($cacheKey)) {
            return false;
        }

        $ttl = max(1, $expiresAt->getTimestamp() - time());
        $this->cache->set($cacheKey, 1, $ttl);

        return true;
    }
}
