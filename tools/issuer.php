<?php

declare(strict_types=1);

/*
 * Stand-in for the auth server, for functional tests: serves the JWKS of the test issuer.
 *   php -S 127.0.0.1:8001 tools/issuer.php
 * Keys are created by "php tools/rg-cli.php init" (and replaced by "rotate").
 */

use function GuillaumeTissier\ResourceGuard\Tools\readJson;
use function GuillaumeTissier\ResourceGuard\Tools\writeJson;

require __DIR__.'/bootstrap.php';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', \PHP_URL_PATH);
header('Content-Type: application/json');

if ('/.well-known/jwks.json' === $path) {
    // Counted so the checks can verify the resource server's caching and refresh rate limit.
    $stats = readJson('issuer-stats.json', ['jwks_fetches' => 0]);
    ++$stats['jwks_fetches'];
    writeJson('issuer-stats.json', $stats);

    $issuer = readJson('issuer.json');
    echo json_encode(['keys' => array_map(
        static fn (array $jwk): array => array_intersect_key($jwk, array_flip(['kty', 'kid', 'use', 'alg', 'n', 'e'])),
        isset($issuer['key']) ? [$issuer['key']] : [],
    )]);

    return;
}

http_response_code(404);
echo json_encode(['error' => 'not_found']);
