<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * Key set known in advance: a JWKS document or the auth server's public key PEM file.
 * Useful for tests and for deployments that ship the public key with the application.
 */
final readonly class StaticJwksProvider implements JwksProviderInterface
{
    public function __construct(private JWKSet $keySet)
    {
    }

    public static function fromJwksJson(string $json): self
    {
        return new self(JWKSet::createFromJson($json));
    }

    public static function fromPublicKeyFile(string $path): self
    {
        return new self(new JWKSet([JWKFactory::createFromKeyFile($path, null, ['use' => 'sig', 'alg' => 'RS256'])]));
    }

    public function getKeySet(bool $forceRefresh = false): JWKSet
    {
        return $this->keySet;
    }
}
