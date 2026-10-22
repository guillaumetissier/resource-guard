<?php

declare(strict_types=1);

/*
 * Functional test tool for resource-guard, without the auth server.
 *
 *   php tools/rg-cli.php check                 runs every scenario against fresh servers, prints PASS/FAIL
 *   php tools/rg-cli.php init                  creates the test issuer key, the client DPoP key, the config
 *   php tools/rg-cli.php serve                 starts the issuer (8001) and the demo API (8000) for manual tests
 *   php tools/rg-cli.php token [options]       issues an access token (see "help")
 *   php tools/rg-cli.php call METHOD URL       calls the demo API with the last token and a fresh DPoP proof
 *   php tools/rg-cli.php webhook TYPE          sends a signed webhook to the demo API
 *   php tools/rg-cli.php rotate                replaces the issuer signing key
 *   php tools/rg-cli.php decode [TOKEN]        shows the claims of a token
 */

use GuillaumeTissier\ResourceGuard\Client\DpopProofFactory;
use GuillaumeTissier\ResourceGuard\Token\OpenSslRS256;
use GuillaumeTissier\ResourceGuard\Util\Json;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookSignature;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

use function GuillaumeTissier\ResourceGuard\Tools\obj;
use function GuillaumeTissier\ResourceGuard\Tools\readJson;
use function GuillaumeTissier\ResourceGuard\Tools\state;
use function GuillaumeTissier\ResourceGuard\Tools\str;
use function GuillaumeTissier\ResourceGuard\Tools\writeJson;

require __DIR__.'/bootstrap.php';

const DEFAULT_API = 'http://127.0.0.1:8000';
const DEFAULT_ISSUER = 'http://127.0.0.1:8001';

// ---------------------------------------------------------------- helpers

/**
 * @param list<string> $argv
 *
 * @return array{list<string>, array<string, string|true>}
 */
function parseArgs(array $argv): array
{
    $args = [];
    $opts = [];
    foreach ($argv as $arg) {
        if (str_starts_with($arg, '--')) {
            $pair = explode('=', substr($arg, 2), 2);
            $opts[$pair[0]] = $pair[1] ?? true;
        } else {
            $args[] = $arg;
        }
    }

    return [$args, $opts];
}

function b64(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function newRsaKey(): JWK
{
    return JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => bin2hex(random_bytes(8))]);
}

function init(string $issuerUrl = DEFAULT_ISSUER): void
{
    writeJson('issuer.json', ['key' => newRsaKey()->all()]);
    writeJson('client.json', ['key' => DpopProofFactory::withNewKey()->privateKey()->all()]);
    writeJson('config.json', [
        'issuer' => $issuerUrl,
        'allowed_clients' => ['my-spa'],
        'require_dpop' => true,
        'webhook_secret' => bin2hex(random_bytes(32)),
    ]);
    writeJson('issuer-stats.json', ['jwks_fetches' => 0]);
    array_map('unlink', glob(state('cache').'/*') ?: []);
}

function client(): DpopProofFactory
{
    $key = obj(readJson('client.json'), 'key');
    if ([] === $key) {
        throw new RuntimeException('Run "php tools/rg-cli.php init" first.');
    }

    return new DpopProofFactory(new JWK($key));
}

/**
 * Options: sub, client, scopes, ttl, expired, bearer, act, mode, dom, acl, forged, alg-none.
 *
 * @param array<string, string|true> $o
 */
function issueToken(array $o): string
{
    $now = time();
    $claims = [
        'aud' => (string) ($o['client'] ?? 'my-spa'),
        'jti' => bin2hex(random_bytes(16)),
        'iat' => $now,
        'nbf' => $now,
        'exp' => isset($o['expired']) ? $now - 3600 : $now + (int) ($o['ttl'] ?? 900),
        'sub' => (string) ($o['sub'] ?? '42'),
        'scopes' => array_values(array_filter(explode(' ', (string) ($o['scopes'] ?? 'profile')))),
    ];
    if (!isset($o['bearer'])) {
        $claims['cnf'] = ['jkt' => client()->thumbprint()];
    }
    if (isset($o['act'])) {
        $claims['act'] = ['sub' => (string) $o['act']];
        $claims['imp'] = 'imp-'.bin2hex(random_bytes(4));
        $claims['imp_mode'] = (string) ($o['mode'] ?? 'read_only');
    }
    if (isset($o['dom'])) {
        $claims['dom'] = (string) $o['dom'];
    }
    if (isset($o['acl'])) {
        // "/a1/a10/+=*:r vehicle:w;/a1/a10/a100/=invoice:w"   ("+" = including subdomains)
        $claims['acl'] = [];
        foreach (array_filter(explode(';', (string) $o['acl'])) as $entry) {
            [$path, $expression] = explode('=', $entry, 2);
            $claims['acl'][] = [rtrim($path, '+'), str_ends_with($path, '+'), $expression];
        }
    }

    if (isset($o['alg-none'])) {
        return b64('{"alg":"none","typ":"JWT"}').'.'.b64((string) json_encode($claims)).'.';
    }

    $key = isset($o['forged']) ? newRsaKey() : new JWK(obj(readJson('issuer.json'), 'key'));
    $jws = (new JWSBuilder(new AlgorithmManager([new OpenSslRS256()])))
        ->create()
        ->withPayload((string) json_encode($claims))
        ->addSignature($key, ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $key->get('kid')])
        ->build();

    return (new CompactSerializer())->serialize($jws, 0);
}

/**
 * Proof options: proof-key=other, proof-url, proof-method, proof-iat (offset in seconds), no-ath.
 *
 * @param array<string, string|true> $o
 */
function proof(string $method, string $url, ?string $token, array $o = []): string
{
    $factory = isset($o['proof-key']) ? DpopProofFactory::withNewKey() : client();
    $htu = (string) ($o['proof-url'] ?? strtok($url, '?'));

    return $factory->create(
        (string) ($o['proof-method'] ?? $method),
        $htu,
        isset($o['no-ath']) ? null : $token,
        null,
        time() + (int) ($o['proof-iat'] ?? 0),
    );
}

/**
 * @param list<string> $headers
 *
 * @return array{int, array<string, string>, array<string, mixed>, string} status, headers, JSON object (or []), raw body
 */
function http(string $method, string $url, array $headers = [], ?string $body = null): array
{
    $responseHeaders = [];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        \CURLOPT_CUSTOMREQUEST => $method ?: 'GET',
        \CURLOPT_RETURNTRANSFER => true,
        \CURLOPT_HTTPHEADER => $headers,
        \CURLOPT_TIMEOUT => 15,
        \CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$responseHeaders): int {
            if (str_contains($line, ':')) {
                [$name, $value] = explode(':', $line, 2);
                $responseHeaders[strtolower(trim($name))] = trim($value);
            }

            return strlen($line);
        },
    ]);
    if (null !== $body) {
        curl_setopt($ch, \CURLOPT_POSTFIELDS, $body);
    }
    $content = curl_exec($ch);
    if (false === $content) {
        throw new RuntimeException(sprintf('%s %s: %s', $method, $url, curl_error($ch)));
    }
    $content = (string) $content;

    return [(int) curl_getinfo($ch, \CURLINFO_RESPONSE_CODE), $responseHeaders, Json::object(json_decode($content, true)) ?? [], $content];
}

/**
 * @param array<string, string|true> $o
 *
 * @return array{int, array<string, string>, array<string, mixed>, string}
 */
function callApi(string $method, string $url, ?string $token, array $o = []): array
{
    $headers = [];
    if (null !== $token) {
        $headers[] = 'Authorization: '.(isset($o['bearer']) ? 'Bearer ' : 'DPoP ').$token;
    }
    if (null !== $token && !isset($o['no-proof'])) {
        $headers[] = 'DPoP: '.($o['proof'] ?? proof($method, $url, $token, $o));
    }

    return http($method, $url, $headers, in_array($method, ['POST', 'PUT', 'PATCH'], true) ? '{}' : null);
}

/**
 * @param array<string, string|true> $o
 *
 * @return array{int, array<string, string>, array<string, mixed>, string}
 */
function sendWebhook(string $apiUrl, string $type, array $o = []): array
{
    $payload = (string) json_encode([
        'id' => (string) ($o['id'] ?? 'evt_'.bin2hex(random_bytes(8))),
        'type' => $type,
        'occurred_at' => date(\DATE_ATOM),
        'data' => ['user_id' => (string) ($o['user'] ?? '42')],
    ]);
    $secret = isset($o['bad-signature']) ? str_repeat('x', 64) : str(readJson('config.json'), 'webhook_secret');
    $timestamp = isset($o['old']) ? time() - 3600 : time();

    return http('POST', $apiUrl.'/webhook', [
        'Content-Type: application/json',
        WebhookSignature::HEADER.': '.(new WebhookSignature($secret))->sign($payload, $timestamp),
    ], $payload);
}

/**
 * @return list<resource>
 */
function startServers(int $apiPort, int $issuerPort, bool $quiet): array
{
    $env = getenv() + ['RG_STATE' => state()];
    $spec = $quiet ? [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']] : [];
    $processes = [];
    foreach ([[$issuerPort, 'issuer.php'], [$apiPort, 'demo-api.php']] as [$port, $script]) {
        $process = proc_open([\PHP_BINARY, '-S', '127.0.0.1:'.$port, __DIR__.'/'.$script], $spec, $pipes, null, $env);
        if (false === $process) {
            throw new RuntimeException('Cannot start the PHP built-in server.');
        }
        $processes[] = $process;
    }
    for ($i = 0; $i < 50; ++$i) {
        $up = @file_get_contents('http://127.0.0.1:'.$apiPort.'/health') && @file_get_contents('http://127.0.0.1:'.$issuerPort.'/.well-known/jwks.json');
        if ($up) {
            return $processes;
        }
        usleep(100_000);
    }
    throw new RuntimeException('The test servers did not start.');
}

function freePort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0');
    if (false === $socket) {
        throw new RuntimeException('Cannot find a free port.');
    }
    $address = (string) stream_socket_get_name($socket, false);
    fclose($socket);

    return (int) substr($address, (int) strrpos($address, ':') + 1);
}

// ---------------------------------------------------------------- check

/**
 * @param array{int, array<string, string>, array<string, mixed>, string}    $response
 * @param (callable(array<string, mixed>, array<string, string>): bool)|null $extra
 *
 * @return array{bool, string, string} passed, scenario, what was received
 */
function verdict(string $name, array $response, int $status, ?string $error = null, ?callable $extra = null): array
{
    [$code, $headers, $body] = $response;
    $ok = $code === $status
        && (null === $error || str($body, 'error') === $error)
        && (null === $extra || $extra($body, $headers));

    return [$ok, $name, sprintf('%d %s', $code, str($body, 'error'))];
}

function check(): int
{
    $tmp = sys_get_temp_dir().'/rg-check-'.bin2hex(random_bytes(4));
    putenv('RG_STATE='.$tmp);
    $apiPort = freePort();
    $issuerPort = freePort();
    $api = 'http://127.0.0.1:'.$apiPort;
    init('http://127.0.0.1:'.$issuerPort);
    $processes = startServers($apiPort, $issuerPort, true);

    $results = [];
    $none = [200, [], [], ''];
    $fetches = static function (): int {
        $count = readJson('issuer-stats.json')['jwks_fetches'] ?? 0;

        return is_int($count) ? $count : 0;
    };
    $whoami = $api.'/api/whoami';

    try {
        // --- Authentication
        $results[] = verdict('No token: 401 with a DPoP challenge', callApi('GET', $whoami, null), 401, 'unauthorized',
            static fn (array $b, array $h): bool => str_starts_with($h['www-authenticate'] ?? '', 'DPoP'));
        $token = issueToken([]);
        $results[] = verdict('DPoP-bound token + valid proof: accepted', callApi('GET', $whoami, $token), 200, null,
            static fn (array $b): bool => '42' === $b['user_id'] && true === $b['dpop']);
        $before = $fetches();
        callApi('GET', $whoami, $token);
        $results[] = verdict('JWKS cached between requests', $none, 200, null, static fn (): bool => $fetches() === $before);

        // --- DPoP attacks
        $results[] = verdict('DPoP-bound token sent as Bearer: refused', callApi('GET', $whoami, $token, ['bearer' => true, 'no-proof' => true]), 401, 'invalid_token');
        $results[] = verdict('Token without proof: refused', callApi('GET', $whoami, $token, ['no-proof' => true]), 401, 'invalid_dpop_proof');
        $results[] = verdict('Proof signed by another key (stolen token): refused', callApi('GET', $whoami, $token, ['proof-key' => 'other']), 401, 'invalid_dpop_proof');
        $proof = proof('GET', $whoami, $token);
        callApi('GET', $whoami, $token, ['proof' => $proof]);
        $results[] = verdict('Replayed proof: refused', callApi('GET', $whoami, $token, ['proof' => $proof]), 401, 'invalid_dpop_proof');
        $results[] = verdict('Proof for another URL: refused', callApi('GET', $whoami, $token, ['proof-url' => $api.'/api/vehicles']), 401, 'invalid_dpop_proof');
        $results[] = verdict('Proof for another method: refused', callApi('GET', $whoami, $token, ['proof-method' => 'POST']), 401, 'invalid_dpop_proof');
        $results[] = verdict('Proof without the token hash (ath): refused', callApi('GET', $whoami, $token, ['no-ath' => true]), 401, 'invalid_dpop_proof');
        $results[] = verdict('Proof issued 10 minutes ago: refused', callApi('GET', $whoami, $token, ['proof-iat' => '-600']), 401, 'invalid_dpop_proof');
        $results[] = verdict('Plain Bearer token while DPoP is required: refused', callApi('GET', $whoami, issueToken(['bearer' => true]), ['bearer' => true, 'no-proof' => true]), 401);

        // --- Token attacks
        $results[] = verdict('Expired token: refused', callApi('GET', $whoami, issueToken(['expired' => true])), 401, 'invalid_token');
        $results[] = verdict('Unsigned token (alg none): refused', callApi('GET', $whoami, issueToken(['alg-none' => true])), 401, 'invalid_token');
        $before = $fetches();
        $results[] = verdict('Token signed by an unknown key: refused', callApi('GET', $whoami, issueToken(['forged' => true])), 401, 'invalid_token');
        callApi('GET', $whoami, issueToken(['forged' => true]));
        callApi('GET', $whoami, issueToken(['forged' => true]));
        $results[] = verdict('Forged tokens trigger at most one JWKS refresh per minute', $none, 200, null,
            static fn (): bool => $fetches() - $before <= 1);
        $results[] = verdict('Token issued to a client not allowed: refused', callApi('GET', $whoami, issueToken(['client' => 'other-app'])), 401, 'invalid_token');
        $tampered = explode('.', $token);
        $tampered[1] = b64((string) json_encode(['sub' => '1'] + (Json::object(json_decode(base64_decode(strtr($tampered[1], '-_', '+/')), true)) ?? [])));
        $results[] = verdict('Tampered payload: refused', callApi('GET', $whoami, implode('.', $tampered)), 401, 'invalid_token');

        // --- Scopes and impersonation
        $acl = '/a1/a10/+=*:r vehicle:w user:w:own';
        $writer = issueToken(['scopes' => 'profile vehicles.write', 'dom' => '/a1/a10/', 'acl' => $acl]);
        $results[] = verdict('Scope present: write allowed', callApi('POST', $api.'/api/vehicles?domain=/a1/a10/', $writer), 201);
        $results[] = verdict('Scope missing: write refused', callApi('POST', $api.'/api/vehicles?domain=/a1/a10/', issueToken(['dom' => '/a1/a10/', 'acl' => $acl])), 403, 'insufficient_scope');
        $readOnly = issueToken(['scopes' => 'profile vehicles.write', 'dom' => '/a1/a10/', 'acl' => $acl, 'act' => '7', 'mode' => 'read_only']);
        $results[] = verdict('Read-only impersonation: reads allowed, actor visible', callApi('GET', $whoami, $readOnly), 200, null,
            static fn (array $b): bool => '7' === $b['impersonated_by'] && true === $b['read_only']);
        $results[] = verdict('Read-only impersonation: writes refused', callApi('POST', $api.'/api/vehicles?domain=/a1/a10/', $readOnly), 403, 'impersonation_read_only');
        $full = issueToken(['scopes' => 'profile vehicles.write', 'dom' => '/a1/a10/', 'acl' => $acl, 'act' => '7', 'mode' => 'full']);
        $results[] = verdict('Full impersonation: writes allowed, actor recorded', callApi('POST', $api.'/api/vehicles?domain=/a1/a10/', $full), 201, null,
            static fn (array $b): bool => '7' === $b['on_behalf_of']);

        // --- Domains and rights
        $results[] = verdict('Read in a subdomain (inherited): allowed', callApi('GET', $api.'/api/vehicles?domain=/a1/a10/a100/', $writer), 200, null,
            static fn (array $b): bool => 'write' === $b['level']);
        $results[] = verdict('Write in a subdomain (inherited): allowed', callApi('POST', $api.'/api/vehicles?domain=/a1/a10/a101/', $writer), 201);
        $results[] = verdict('Parent domain: refused', callApi('GET', $api.'/api/vehicles?domain=/a1/', $writer), 403, 'forbidden');
        $results[] = verdict('Sibling domain: refused', callApi('GET', $api.'/api/vehicles?domain=/a1/a11/', $writer), 403, 'forbidden');
        $results[] = verdict('Look-alike path (/a1/a10x/): refused', callApi('GET', $api.'/api/vehicles?domain=/a1/a10x/', $writer), 403, 'forbidden');
        $narrow = issueToken(['scopes' => 'profile vehicles.write', 'dom' => '/a1/a10/', 'acl' => '/a1/a10/+=*:r;/a1/a10/a100/=vehicle:w']);
        $results[] = verdict('Grant limited to one subdomain: write there', callApi('POST', $api.'/api/vehicles?domain=/a1/a10/a100/', $narrow), 201);
        $results[] = verdict('Grant limited to one subdomain: read only elsewhere', callApi('POST', $api.'/api/vehicles?domain=/a1/a10/a101/', $narrow), 403, 'forbidden');
        $sneaky = issueToken(['dom' => '/a1/a10/', 'acl' => '/a1/+=*:m']);
        $results[] = verdict('Entry above the user\'s domain in the token: ignored', callApi('GET', $api.'/api/vehicles?domain=/a1/a10/', $sneaky), 403, 'forbidden');
        $results[] = verdict('Own profile (user:w:own): update allowed', callApi('PUT', $api.'/api/profiles/42?domain=/a1/a10/', $writer), 200);
        $results[] = verdict('Someone else\'s profile: refused', callApi('PUT', $api.'/api/profiles/43?domain=/a1/a10/', $writer), 403, 'forbidden');
        $results[] = verdict('Token without rights: refused', callApi('GET', $api.'/api/vehicles?domain=/a1/a10/', issueToken([])), 403, 'forbidden');

        // --- Key rotation
        $old = issueToken([]);
        writeJson('issuer.json', ['key' => newRsaKey()->all()]);
        $cacheDir = state('cache');
        foreach (glob($cacheDir.'/*') ?: [] as $file) {
            // Simulate the rate-limit window being over (a real rotation is rarer than once a minute).
            $data = unserialize((string) file_get_contents($file));
            if (is_array($data) && is_int($data[1] ?? null)) {
                unlink($file);
            }
        }
        $results[] = verdict('After key rotation, new tokens accepted (JWKS refreshed)', callApi('GET', $whoami, issueToken([])), 200);
        $results[] = verdict('After key rotation, tokens of the removed key refused', callApi('GET', $whoami, $old), 401, 'invalid_token');

        // --- Webhooks
        $results[] = verdict('Signed webhook: accepted', sendWebhook($api, 'user.locked', ['id' => 'evt_1']), 202, null,
            static fn (array $b): bool => '42' === $b['user_id']);
        $results[] = verdict('Redelivered webhook: recognised as duplicate', sendWebhook($api, 'user.locked', ['id' => 'evt_1']), 200, null,
            static fn (array $b): bool => 'duplicate' === $b['status']);
        $results[] = verdict('Webhook with a wrong signature: refused', sendWebhook($api, 'user.locked', ['bad-signature' => true]), 400, 'invalid_signature');
        $results[] = verdict('Webhook signed an hour ago (replay): refused', sendWebhook($api, 'user.locked', ['old' => true]), 400, 'invalid_signature');
    } finally {
        foreach ($processes as $process) {
            proc_terminate($process);
        }
        array_map('unlink', glob($tmp.'/cache/*') ?: []);
        @rmdir($tmp.'/cache');
        array_map('unlink', glob($tmp.'/*') ?: []);
        @rmdir($tmp);
    }

    $failed = 0;
    foreach ($results as [$ok, $name, $detail]) {
        $failed += $ok ? 0 : 1;
        printf("  %s  %-62s %s\n", $ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m", $name, $ok ? '' : '→ got '.$detail);
    }
    printf("\n%d/%d scenarios passed\n", count($results) - $failed, count($results));

    return 0 === $failed ? 0 : 1;
}

// ---------------------------------------------------------------- help

function help(?string $command): string
{
    $topics = [
        'check' => <<<'TXT'
            check

              Starts a test issuer and the demo API on free ports, runs every scenario against them,
              prints one PASS/FAIL line per scenario, then stops the servers.
              Exit code 0 when everything passes, 1 otherwise (usable in CI).

              Nothing to prepare: it uses its own temporary keys and state.

              Example:
                php tools/rg-cli.php check

            TXT,
        'init' => <<<'TXT'
            init [--issuer=URL]

              Creates, in .rg-test/ (or the directory in RG_STATE):
                - the signing key of the test issuer (stands for the auth server),
                - the DPoP key of the test client (stands for the browser application),
                - the demo API configuration (allowed client "my-spa", DPoP required, webhook secret).
              Running it again starts from scratch.

              --issuer=URL   where the demo API fetches the JWKS (default http://127.0.0.1:8001)

            TXT,
        'serve' => <<<'TXT'
            serve

              Starts the two test servers and keeps running (Ctrl+C to stop):
                http://127.0.0.1:8001   test issuer: /.well-known/jwks.json
                http://127.0.0.1:8000   demo API (see "help call" for its endpoints)
              Run "init" first. Use another terminal for the other commands.

            TXT,
        'token' => <<<'TXT'
            token [options]

              Issues an access token signed by the test issuer, prints it and keeps it for "call".
              Without options: user 42, client my-spa, scope "profile", valid 15 minutes, bound to
              the test client's DPoP key.

              Who and what:
                --sub=ID            user id (the "sub" claim)                          default 42
                --client=ID         client the token was issued to                     default my-spa
                --scopes="A B"      space-separated scopes                             default "profile"
                --ttl=SECONDS       lifetime                                           default 900

              Domains and rights (the "dom" and "acl" claims):
                --dom=PATH          the user's domain, e.g. /a1/a10/
                --acl="RULES"       rights, entries separated by ";", each "PATH=EXPRESSION";
                                    a "+" after the path extends the entry to the subdomains:
                                      --acl="/a1/a10/+=*:r vehicle:w"
                                      --acl="/a1/a10/+=*:r;/a1/a10/a100/=vehicle:w"

              Impersonation:
                --act=ID            an administrator (this id) acts on behalf of the user
                --mode=MODE         read_only (default) or full

              Broken tokens, to see them refused:
                --expired           expired an hour ago
                --bearer            not bound to a DPoP key (plain Bearer token)
                --forged            signed by a key the issuer does not publish
                --alg-none          not signed at all

              Examples:
                php tools/rg-cli.php token
                php tools/rg-cli.php token --scopes="profile vehicles.write" --dom=/a1/a10/ --acl="/a1/a10/+=*:r vehicle:w"
                php tools/rg-cli.php token --act=7 --mode=read_only

            TXT,
        'call' => <<<'TXT'
            call METHOD URL [options]

              Calls the demo API with the last token (from "token") and a fresh DPoP proof, then
              prints the HTTP status and the JSON response.

              Demo API endpoints:
                GET  /api/whoami                            who is calling (any valid token)
                GET  /api/vehicles?domain=PATH              needs vehicle:r on PATH
                POST /api/vehicles?domain=PATH              needs vehicle:w on PATH and the scope vehicles.write
                PUT  /api/profiles/ID?domain=PATH           needs user:w, or user:w:own when ID is the caller
                GET  /health

              Options:
                --token=JWT         use this token instead of the last one
                --anonymous         send no token at all
                --bearer            send the token as "Bearer" instead of "DPoP"
                --no-proof          send no DPoP proof

              Broken proofs, to see them refused:
                --proof-key=other   proof signed by another key (simulates a stolen token)
                --proof-url=URL     proof made for another URL
                --proof-method=M    proof made for another HTTP method
                --proof-iat=-600    proof dated 600 seconds ago
                --no-ath            proof without the hash of the token

              Examples:
                php tools/rg-cli.php call GET http://127.0.0.1:8000/api/whoami
                php tools/rg-cli.php call GET "http://127.0.0.1:8000/api/vehicles?domain=/a1/a10/a100/"
                php tools/rg-cli.php call POST "http://127.0.0.1:8000/api/vehicles?domain=/a1/a10/"
                php tools/rg-cli.php call GET http://127.0.0.1:8000/api/whoami --proof-key=other

            TXT,
        'proof' => <<<'TXT'
            proof METHOD URL [--token=JWT]

              Prints a DPoP proof for the last token, to use with curl or another HTTP client:
                curl -H "Authorization: DPoP $(jq -r .access_token .rg-test/token.json)" \
                     -H "DPoP: $(php tools/rg-cli.php proof GET http://127.0.0.1:8000/api/whoami)" \
                     http://127.0.0.1:8000/api/whoami
              A proof is valid for one request only.

            TXT,
        'webhook' => <<<'TXT'
            webhook [TYPE] [options]

              Sends a signed auth server event to the demo API (POST /webhook). TYPE defaults to
              user.locked. Answers: 202 accepted, 200 duplicate (same event id), 400 bad signature.

                --user=ID           user concerned                                      default 42
                --id=ID             event id; send the same id twice to see the duplicate detected
                --bad-signature     signed with the wrong secret
                --old               signed an hour ago (replay)
                --api=URL           demo API address                                    default http://127.0.0.1:8000

            TXT,
        'rotate' => <<<'TXT'
            rotate

              Replaces the issuer's signing key. New tokens are accepted (the demo API fetches the new
              JWKS when it meets an unknown key); tokens signed with the old key are refused.

            TXT,
        'decode' => <<<'TXT'
            decode [TOKEN]

              Shows the header and the claims of a token (the last one by default). No verification.

            TXT,
    ];

    if (null !== $command && isset($topics[$command])) {
        return $topics[$command];
    }

    return <<<'TXT'
        rg-cli: functional test tool for resource-guard (no auth server needed)

        Usage: php tools/rg-cli.php COMMAND [arguments] [options]

        Automatic check
          check               start test servers, run every scenario, print PASS/FAIL

        Manual testing, step by step
          1. php tools/rg-cli.php init                 create test keys and config (once)
          2. php tools/rg-cli.php serve                start the test servers, leave it running
          3. php tools/rg-cli.php token                in another terminal: get an access token
          4. php tools/rg-cli.php call GET http://127.0.0.1:8000/api/whoami
                                                       call the demo API with it

        Commands
          check               automatic check of every scenario
          init                create the test keys and config
          serve               start the test issuer (port 8001) and the demo API (port 8000)
          token               issue an access token (user, scopes, rights, impersonation, broken tokens)
          call                call the demo API with the token and a DPoP proof
          proof               print a DPoP proof, for curl
          webhook             send a signed event to the demo API
          rotate              change the issuer's signing key
          decode              show the claims of a token
          help COMMAND        details and options of a command, e.g. "help token"

        TXT;
}

// ---------------------------------------------------------------- commands

[$args, $opts] = parseArgs(array_slice($argv, 1));
$command = array_shift($args) ?? 'help';

try {
    switch ($command) {
        case 'check':
            exit(check());

        case 'init':
            init((string) ($opts['issuer'] ?? DEFAULT_ISSUER));
            echo 'Issuer key, client DPoP key and config written to '.state()."\n";
            break;

        case 'serve':
            echo 'Issuer on '.DEFAULT_ISSUER.', demo API on '.DEFAULT_API." (Ctrl+C to stop)\n";
            $processes = startServers(8000, 8001, false);
            while (0 === sleep(1)) {
                // Until Ctrl+C, which also stops the two servers (same process group).
            }
            break;

        case 'token':
            $token = issueToken($opts);
            writeJson('token.json', ['access_token' => $token]);
            echo $token."\n";
            break;

        case 'proof':
            echo proof(strtoupper($args[0] ?? 'GET'), $args[1] ?? DEFAULT_API.'/api/whoami', is_string($opts['token'] ?? null) ? $opts['token'] : (str(readJson('token.json'), 'access_token') ?: null), $opts)."\n";
            break;

        case 'call':
            $token = is_string($opts['token'] ?? null) ? $opts['token'] : (str(readJson('token.json'), 'access_token') ?: null);
            [$status, , $body, $raw] = callApi(strtoupper($args[0] ?? 'GET'), $args[1] ?? DEFAULT_API.'/api/whoami', isset($opts['anonymous']) ? null : $token, $opts);
            echo $status."\n".([] !== $body ? json_encode($body, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES) : $raw)."\n";
            break;

        case 'webhook':
            [$status, , $body] = sendWebhook((string) ($opts['api'] ?? DEFAULT_API), $args[0] ?? 'user.locked', $opts);
            echo $status."\n".json_encode($body, \JSON_PRETTY_PRINT)."\n";
            break;

        case 'rotate':
            writeJson('issuer.json', ['key' => newRsaKey()->all()]);
            echo "New issuer key. Tokens signed with the previous one are now refused (after the JWKS refresh).\n";
            break;

        case 'decode':
            $token = $args[0] ?? str(readJson('token.json'), 'access_token');
            [$h, $p] = array_pad(explode('.', $token), 2, '');
            $dec = static fn (string $part): mixed => json_decode((string) base64_decode(strtr($part, '-_', '+/')), true);
            echo json_encode(['header' => $dec($h), 'claims' => $dec($p)], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES)."\n";
            break;

        case 'help':
        default:
            echo help($args[0] ?? null);
    }
} catch (Throwable $e) {
    fwrite(\STDERR, 'Error: '.$e->getMessage()."\n");
    exit(1);
}
