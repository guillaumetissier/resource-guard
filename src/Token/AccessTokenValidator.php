<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

use GuillaumeTissier\ResourceGuard\Util\SystemClock;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;

/**
 * Verifies the JWT access tokens issued by the auth server, offline, using its JWKS.
 */
final class AccessTokenValidator
{
    private readonly JWSVerifier $verifier;
    private readonly CompactSerializer $serializer;
    private readonly ClockInterface $clock;

    /**
     * @param list<string> $allowedClientIds accept only tokens issued to these clients (empty = any client)
     */
    public function __construct(
        private readonly JwksProviderInterface $jwksProvider,
        private readonly array $allowedClientIds = [],
        ?ClockInterface $clock = null,
        private readonly int $leewaySeconds = 30,
    ) {
        $this->clock = $clock ?? new SystemClock();
        $this->serializer = new CompactSerializer();
        // The auth server signs with RS256 only; pinning the algorithm prevents alg-confusion attacks.
        $this->verifier = new JWSVerifier(new AlgorithmManager([new OpenSslRS256()]));
    }

    /**
     * @throws InvalidTokenException
     */
    public function validate(string $rawToken): AccessToken
    {
        try {
            $jws = $this->serializer->unserialize($rawToken);
        } catch (\Throwable) {
            throw InvalidTokenException::because('malformed token');
        }

        if (1 !== $jws->countSignatures() || ($jws->getSignature(0)->getProtectedHeader()['alg'] ?? null) !== 'RS256') {
            throw InvalidTokenException::because('unexpected token algorithm');
        }

        if (!$this->verifySignature($jws, false) && !$this->verifySignature($jws, true)) {
            throw InvalidTokenException::because('invalid token signature');
        }

        $claims = json_decode((string) $jws->getPayload(), true);
        if (!\is_array($claims)) {
            throw InvalidTokenException::because('malformed token payload');
        }

        $now = $this->clock->now()->getTimestamp();

        $exp = $claims['exp'] ?? null;
        if (!is_numeric($exp) || (int) $exp < $now - $this->leewaySeconds) {
            throw InvalidTokenException::because('token expired');
        }
        $nbf = $claims['nbf'] ?? null;
        if (is_numeric($nbf) && (int) $nbf > $now + $this->leewaySeconds) {
            throw InvalidTokenException::because('token not yet valid');
        }

        $jti = $claims['jti'] ?? null;
        $sub = $claims['sub'] ?? null;
        if (!\is_string($jti) || !\is_string($sub) || '' === $sub) {
            throw InvalidTokenException::because('token misses jti or sub');
        }

        $aud = $claims['aud'] ?? null;
        $audiences = \is_array($aud) ? array_values(array_filter($aud, 'is_string')) : (\is_string($aud) ? [$aud] : []);
        if ([] === $audiences) {
            throw InvalidTokenException::because('token misses aud');
        }
        if ([] !== $this->allowedClientIds && [] === array_intersect($audiences, $this->allowedClientIds)) {
            throw InvalidTokenException::because('token was not issued to an allowed client');
        }

        $scopes = $claims['scopes'] ?? [];
        $scopes = \is_array($scopes) ? array_values(array_filter($scopes, 'is_string')) : [];

        $jkt = $claims['cnf']['jkt'] ?? null;

        return new AccessToken(
            id: $jti,
            subject: $sub,
            clientId: $audiences[0],
            scopes: $scopes,
            expiresAt: new \DateTimeImmutable('@'.(int) $exp),
            jkt: \is_string($jkt) ? $jkt : null,
            claims: $claims,
            raw: $rawToken,
        );
    }

    private function verifySignature(JWS $jws, bool $forceRefresh): bool
    {
        try {
            return $this->verifier->verifyWithKeySet($jws, $this->jwksProvider->getKeySet($forceRefresh), 0);
        } catch (\Throwable) {
            return false;
        }
    }
}
