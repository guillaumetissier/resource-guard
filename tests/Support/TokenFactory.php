<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Support;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Issues access tokens shaped like the auth server's ones (league/oauth2-server claims).
 */
final class TokenFactory
{
    public readonly JWK $key;

    public function __construct()
    {
        $this->key = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
    }

    public function keySet(): JWKSet
    {
        return new JWKSet([$this->key->toPublic()]);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    public function issue(array $overrides = [], ?JWK $signingKey = null): string
    {
        $now = time();
        $claims = array_merge([
            'aud' => 'spa-client',
            'jti' => bin2hex(random_bytes(8)),
            'iat' => $now + 0.123,
            'nbf' => $now + 0.123,
            'exp' => $now + 3600.5,
            'sub' => '42',
            'scopes' => ['profile'],
        ], $overrides);
        $claims = array_filter($claims, static fn ($v) => null !== $v);

        $jws = (new JWSBuilder(new AlgorithmManager([new RS256()])))
            ->create()
            ->withPayload((string) json_encode($claims))
            ->addSignature($signingKey ?? $this->key, ['alg' => 'RS256', 'typ' => 'JWT'])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }
}
