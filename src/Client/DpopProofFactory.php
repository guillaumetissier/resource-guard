<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Client;

use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Client side of DPoP for PHP callers (server-to-server clients, tests).
 * Browser clients do the same with WebCrypto (see the README).
 */
final readonly class DpopProofFactory
{
    private JWSBuilder $builder;

    public function __construct(private JWK $privateKey)
    {
        $this->builder = new JWSBuilder(new AlgorithmManager([new ES256()]));
    }

    /**
     * Generates a fresh P-256 key pair. Keep it for the whole lifetime of the tokens bound to it.
     */
    public static function withNewKey(): self
    {
        return new self(JWKFactory::createECKey('P-256'));
    }

    public function privateKey(): JWK
    {
        return $this->privateKey;
    }

    /**
     * RFC 7638 thumbprint of the public key: the "jkt" a server binds tokens to.
     */
    public function thumbprint(): string
    {
        return $this->privateKey->toPublic()->thumbprint('sha256');
    }

    /**
     * @param string|null $accessToken pass it when calling a resource server (adds the "ath" claim)
     */
    public function create(string $method, string $uri, ?string $accessToken = null, ?string $nonce = null, ?int $issuedAt = null): string
    {
        $claims = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => strtoupper($method),
            'htu' => $uri,
            'iat' => $issuedAt ?? time(),
        ];
        if (null !== $accessToken) {
            $claims['ath'] = DpopProofValidator::accessTokenHash($accessToken);
        }
        if (null !== $nonce) {
            $claims['nonce'] = $nonce;
        }

        $publicJwk = $this->privateKey->toPublic()->all();
        unset($publicJwk['kid'], $publicJwk['use'], $publicJwk['alg']);

        $jws = $this->builder
            ->create()
            ->withPayload((string) json_encode($claims, \JSON_UNESCAPED_SLASHES))
            ->addSignature($this->privateKey, ['alg' => 'ES256', 'typ' => 'dpop+jwt', 'jwk' => $publicJwk])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
