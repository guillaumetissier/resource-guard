<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Dpop;

/**
 * Remembers DPoP proof identifiers (jti) to reject replayed proofs.
 *
 * Implementations must be shared between all workers of an application
 * (database, Redis, shared cache) - a per-process store only protects one process.
 */
interface ReplayStoreInterface
{
    /**
     * Records the key and reports whether it was unseen.
     *
     * @return bool true if the key was recorded now, false if it was already present (replay)
     */
    public function remember(string $key, \DateTimeImmutable $expiresAt): bool;
}
