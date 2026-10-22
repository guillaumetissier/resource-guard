<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Dpop;

/**
 * Normalizes an HTTP target URI for the DPoP "htu" comparison (RFC 9449 section 4.3, point 9):
 * query and fragment are ignored, scheme and host are case-insensitive, default ports are dropped.
 */
final class HtuNormalizer
{
    public static function normalize(string $uri): string
    {
        $parts = parse_url($uri);
        if (false === $parts || !isset($parts['scheme'], $parts['host'])) {
            throw DpopException::because('htu is not an absolute URI');
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        $port = $parts['port'] ?? null;

        if (('https' === $scheme && 443 === $port) || ('http' === $scheme && 80 === $port)) {
            $port = null;
        }

        $path = $parts['path'] ?? '';
        if ('' === $path) {
            $path = '/';
        }

        return $scheme.'://'.$host.(null !== $port ? ':'.$port : '').$path;
    }
}
