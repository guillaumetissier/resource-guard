<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Webhook;

/**
 * HMAC-SHA256 signature of webhook payloads, shared by the sender (auth server) and receivers.
 *
 * Header format: "t=<unix timestamp>,v1=<hex hmac of '<timestamp>.<raw body>'>".
 * Signing the timestamp lets receivers reject old deliveries (replay protection).
 */
final readonly class WebhookSignature
{
    public const HEADER = 'X-Auth-Server-Signature';

    public function __construct(
        #[\SensitiveParameter] private string $secret,
        private int $toleranceSeconds = 300,
    ) {
        if (\strlen($secret) < 32) {
            throw new \InvalidArgumentException('The webhook secret must be at least 32 characters long.');
        }
    }

    public function sign(string $payload, ?int $timestamp = null): string
    {
        $timestamp ??= time();

        return \sprintf('t=%d,v1=%s', $timestamp, hash_hmac('sha256', $timestamp.'.'.$payload, $this->secret));
    }

    public function verify(string $payload, ?string $header, ?int $now = null): bool
    {
        if (null === $header || !preg_match('/^t=(\d+),v1=([a-f0-9]{64})$/', trim($header), $m)) {
            return false;
        }

        $timestamp = (int) $m[1];
        if (abs(($now ?? time()) - $timestamp) > $this->toleranceSeconds) {
            return false;
        }

        return hash_equals(hash_hmac('sha256', $timestamp.'.'.$payload, $this->secret), $m[2]);
    }
}
