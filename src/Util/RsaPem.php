<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Util;

use Jose\Component\Core\JWK;

/**
 * JWK -> PEM for RSA keys by plain DER encoding of the key bytes.
 *
 * web-token converts keys through big-integer arithmetic, which is pure PHP (hundreds of
 * milliseconds per key) when neither ext-gmp nor ext-bcmath is installed. No arithmetic is
 * needed: the JWK members are already the big-endian bytes of the integers.
 *
 * @internal
 */
final class RsaPem
{
    /** @var array<string, string> PEM by key fingerprint: JWKS keys are reused on every request */
    private static array $cache = [];

    private const OID_RSA_ENCRYPTION = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

    public static function publicKey(JWK $key): string
    {
        $n = self::member($key, 'n');
        $e = self::member($key, 'e');
        $cacheKey = 'pub:'.hash('sha256', $n.'|'.$e);

        return self::$cache[$cacheKey] ??= self::remember(self::pem('PUBLIC KEY', self::sequence(
            self::sequence(self::OID_RSA_ENCRYPTION."\x05\x00")
            ."\x03".self::length(1 + \strlen($rsaPublicKey = self::sequence(self::integer($n).self::integer($e))))."\x00".$rsaPublicKey,
        )));
    }

    /**
     * PKCS#1 private key; the JWK must carry the CRT members (p, q, dp, dq, qi), as generated keys do.
     */
    public static function privateKey(JWK $key): string
    {
        $der = self::integer("\x00");
        foreach (['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'] as $member) {
            $der .= self::integer(self::member($key, $member));
        }

        return self::pem('RSA PRIVATE KEY', self::sequence($der));
    }

    private static function remember(string $pem): string
    {
        if (\count(self::$cache) >= 64) {
            self::$cache = [];
        }

        return $pem;
    }

    private static function member(JWK $key, string $name): string
    {
        $value = $key->has($name) ? $key->get($name) : null;
        if (!\is_string($value) || '' === $value) {
            throw new \InvalidArgumentException(\sprintf('RSA key without "%s".', $name));
        }
        $bytes = base64_decode(strtr($value, '-_', '+/'), true);
        if (false === $bytes || '' === $bytes) {
            throw new \InvalidArgumentException(\sprintf('RSA key member "%s" is not base64url.', $name));
        }

        return $bytes;
    }

    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ('' === $bytes || \ord($bytes[0]) > 0x7F) {
            $bytes = "\x00".$bytes; // DER integers are signed: keep them positive
        }

        return "\x02".self::length(\strlen($bytes)).$bytes;
    }

    private static function sequence(string $content): string
    {
        return "\x30".self::length(\strlen($content)).$content;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return \chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return \chr(0x80 | \strlen($bytes)).$bytes;
    }

    private static function pem(string $label, string $der): string
    {
        return "-----BEGIN {$label}-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END {$label}-----\n";
    }
}
