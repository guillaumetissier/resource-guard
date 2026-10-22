<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Dpop;

/**
 * Raised when a DPoP proof is missing, malformed or fails a check.
 * Maps to the "invalid_dpop_proof" error code of RFC 9449.
 */
final class DpopException extends \RuntimeException
{
    public const ERROR_CODE = 'invalid_dpop_proof';

    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
