<?php

declare(strict_types=1);

/*
 * Stand-in for the auth server, for functional tests: serves the JWKS of the test issuer.
 *   php -S 127.0.0.1:8001 tools/issuer.php
 * Keys are created by "php tools/rg-cli.php init" (and replaced by "rotate").
 */

use function GuillaumeTissier\ResourceGuard\Tools\obj;
use function GuillaumeTissier\ResourceGuard\Tools\readJson;
use function GuillaumeTissier\ResourceGuard\Tools\str;
use function GuillaumeTissier\ResourceGuard\Tools\writeJson;

require __DIR__.'/bootstrap.php';

$path = parse_url(str($_SERVER, 'REQUEST_URI') ?: '/', \PHP_URL_PATH);
header('Content-Type: application/json');

if ('/.well-known/jwks.json' === $path) {
    // Counted so the checks can verify the resource server's caching and refresh rate limit.
    $fetches = readJson('issuer-stats.json')['jwks_fetches'] ?? 0;
    writeJson('issuer-stats.json', ['jwks_fetches' => (is_int($fetches) ? $fetches : 0) + 1]);

    // Public members only.
    $key = obj(readJson('issuer.json'), 'key');
    echo json_encode(['keys' => [] === $key ? [] : [array_intersect_key($key, array_flip(['kty', 'kid', 'use', 'alg', 'n', 'e']))]]);

    return;
}

http_response_code(404);
echo json_encode(['error' => 'not_found']);
