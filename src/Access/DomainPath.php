<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Access;

/**
 * Materialized path of a domain in the domain tree: "/a1/a10/a100/" (codes from the root, slash-delimited).
 */
final class DomainPath
{
    private function __construct()
    {
    }

    public static function normalize(string $path): string
    {
        $codes = array_filter(explode('/', $path), static fn (string $c): bool => '' !== $c);

        return '/'.implode('/', $codes).([] === $codes ? '' : '/');
    }

    /**
     * True when $path is $ancestor itself or one of its descendants.
     */
    public static function isWithin(string $path, string $ancestor): bool
    {
        return str_starts_with(self::normalize($path), self::normalize($ancestor));
    }

    public static function code(string $path): string
    {
        $codes = array_values(array_filter(explode('/', $path), static fn (string $c): bool => '' !== $c));

        return [] === $codes ? '' : $codes[\count($codes) - 1];
    }
}
