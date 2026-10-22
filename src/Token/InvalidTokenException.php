<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

final class InvalidTokenException extends \RuntimeException
{
    public const ERROR_CODE = 'invalid_token';

    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
