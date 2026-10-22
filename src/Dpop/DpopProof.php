<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Dpop;

/**
 * A DPoP proof that passed every check of RFC 9449 section 4.3.
 */
final readonly class DpopProof
{
    /**
     * @param array<string, mixed> $publicJwk the public key embedded in the proof header
     */
    public function __construct(
        public string $jkt,
        public string $jti,
        public string $htm,
        public string $htu,
        public int $iat,
        public array $publicJwk,
        public ?string $ath = null,
        public ?string $nonce = null,
    ) {
    }
}
