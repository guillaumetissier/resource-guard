<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

use GuillaumeTissier\ResourceGuard\Util\RsaPem;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * RS256 (RSASSA-PKCS1-v1_5 with SHA-256) through OpenSSL, with a fast JWK -> PEM conversion
 * (see RsaPem). Drop-in replacement for web-token's RS256, fast with or without ext-gmp.
 */
final readonly class OpenSslRS256 implements SignatureAlgorithm
{
    public function name(): string
    {
        return 'RS256';
    }

    public function allowedKeyTypes(): array
    {
        return ['RSA'];
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        if ('RSA' !== $key->get('kty')) {
            return false;
        }
        try {
            return 1 === openssl_verify($input, $signature, RsaPem::publicKey($key), \OPENSSL_ALGO_SHA256);
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    public function sign(JWK $key, string $input): string
    {
        if (!openssl_sign($input, $signature, RsaPem::privateKey($key), \OPENSSL_ALGO_SHA256) || !\is_string($signature)) {
            throw new \RuntimeException('RS256 signature failed: '.(string) openssl_error_string());
        }

        return $signature;
    }
}
