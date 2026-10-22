<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Dpop;

/**
 * Per-process replay store. Only suitable for tests and single-process setups.
 */
final class InMemoryReplayStore implements ReplayStoreInterface
{
    /** @var array<string, int> key => expiry timestamp */
    private array $seen = [];

    public function remember(string $key, \DateTimeImmutable $expiresAt): bool
    {
        $now = time();
        $this->seen = array_filter($this->seen, static fn (int $exp): bool => $exp > $now);

        if (isset($this->seen[$key])) {
            return false;
        }

        $this->seen[$key] = $expiresAt->getTimestamp();

        return true;
    }
}
