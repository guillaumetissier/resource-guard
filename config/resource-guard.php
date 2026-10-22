<?php

// Laravel configuration. Publish with:
//   php artisan vendor:publish --tag=resource-guard-config

return [
    // JWKS endpoint of the auth server (preferred: supports key rotation).
    'jwks_uri' => env('AUTH_SERVER_JWKS_URI', 'http://auth-server/.well-known/jwks.json'),

    // Alternative to jwks_uri: path to the auth server public key (PEM). Takes precedence when set.
    'public_key_path' => env('AUTH_SERVER_PUBLIC_KEY_PATH'),

    // Only accept tokens issued to these OAuth clients (comma-separated). Empty = any client.
    'allowed_clients' => array_filter(explode(',', (string) env('AUTH_SERVER_ALLOWED_CLIENTS', ''))),

    // Reject plain Bearer tokens: every request must carry a DPoP-bound token and a valid proof.
    'require_dpop' => (bool) env('AUTH_SERVER_REQUIRE_DPOP', true),

    // Tolerated clock skew, and maximum age of a DPoP proof, in seconds.
    'leeway' => 30,
    'dpop_max_age' => 300,

    // Cache store used for JWKS and DPoP replay protection (null = default store).
    // Must be shared between all PHP workers (redis, database, memcached - not "array").
    'cache_store' => env('AUTH_SERVER_CACHE_STORE'),

    // Eloquent model resolved from the token "sub" and set as the authenticated user (null = disabled).
    'user_model' => env('AUTH_SERVER_USER_MODEL', 'App\\Models\\User'),

    'webhook' => [
        // Shared secret (min. 32 chars), identical to WEBHOOK_SECRET on the auth server.
        'secret' => env('AUTH_SERVER_WEBHOOK_SECRET'),
        // Route receiving the events; set to null to register your own route.
        'path' => '/auth-server/webhook',
        'tolerance' => 300,
    ],
];
