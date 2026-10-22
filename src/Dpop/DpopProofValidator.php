<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Dpop;

use DateMalformedStringException;
use GuillaumeTissier\ResourceGuard\Token\OpenSslRS256;
use GuillaumeTissier\ResourceGuard\Util\SystemClock;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;

/**
 * Validates DPoP proof JWTs (RFC 9449 section 4.3).
 *
 * Shared by the authorization server (token endpoint) and by resource servers,
 * so both sides apply exactly the same rules.
 */
final class DpopProofValidator
{
    /** Asymmetric algorithms only: "none" and HMAC are never acceptable for DPoP. */
    public const array SUPPORTED_ALGORITHMS = ['ES256', 'ES384', 'RS256', 'PS256', 'EdDSA'];

    /** JWK members that only exist on private keys. */
    private const array PRIVATE_KEY_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    private const int MAX_PROOF_LENGTH = 8192;

    private readonly JWSVerifier $verifier;
    private readonly CompactSerializer $serializer;
    private readonly ClockInterface $clock;

    /**
     * @param int $maxAgeSeconds how old a proof (iat) may be
     * @param int $leewaySeconds tolerated clock skew for proofs issued "in the future"
     */
    public function __construct(
        private readonly ReplayStoreInterface $replayStore,
        ?ClockInterface $clock = null,
        private readonly int $maxAgeSeconds = 300,
        private readonly int $leewaySeconds = 30,
    ) {
        $this->clock = $clock ?? new SystemClock();
        $this->serializer = new CompactSerializer();
        $this->verifier = new JWSVerifier(new AlgorithmManager([
            new ES256(),
            new ES384(),
            new OpenSslRS256(),
            new PS256(),
            new EdDSA(),
        ]));
    }

    /**
     * @param string      $proof          the raw value of the "DPoP" HTTP header
     * @param string      $httpMethod     method of the request carrying the proof
     * @param string      $httpUri        absolute URI of the request carrying the proof
     * @param string|null $accessToken    when the proof accompanies an access token: checks the "ath" claim
     * @param string|null $expectedJkt    when the token is bound to a key: the proof must be signed by that key
     * @param string|null $expectedNonce  when the server issued a DPoP-Nonce
     *
     * @throws DpopException|DateMalformedStringException
     */
    public function validate(
        string $proof,
        string $httpMethod,
        string $httpUri,
        ?string $accessToken = null,
        ?string $expectedJkt = null,
        ?string $expectedNonce = null,
    ): DpopProof {
        $proof = trim($proof);
        if ('' === $proof || \strlen($proof) > self::MAX_PROOF_LENGTH || str_contains($proof, ',')) {
            // A comma means several DPoP headers were folded together: exactly one is allowed.
            throw DpopException::because('exactly one well-formed DPoP proof is required');
        }

        $jws = $this->parse($proof);
        $header = $jws->getSignature(0)->getProtectedHeader();

        if (($header['typ'] ?? null) !== 'dpop+jwt') {
            throw DpopException::because('typ must be "dpop+jwt"');
        }

        $alg = $header['alg'] ?? null;
        if (!\is_string($alg) || !\in_array($alg, self::SUPPORTED_ALGORITHMS, true)) {
            throw DpopException::because('unsupported alg');
        }

        $jwkValues = $header['jwk'] ?? null;
        if (!\is_array($jwkValues) || !isset($jwkValues['kty']) || 'oct' === $jwkValues['kty']) {
            throw DpopException::because('jwk header must hold an asymmetric public key');
        }
        foreach (self::PRIVATE_KEY_MEMBERS as $member) {
            if (\array_key_exists($member, $jwkValues)) {
                throw DpopException::because('jwk header must not contain private key material');
            }
        }

        try {
            $jwk = new JWK($jwkValues);
            $signatureIsValid = $this->verifier->verifyWithKey($jws, $jwk, 0);
        } catch (\Throwable) {
            throw DpopException::because('unable to verify the proof signature');
        }
        if (!$signatureIsValid) {
            throw DpopException::because('invalid proof signature');
        }

        $claims = json_decode((string) $jws->getPayload(), true);
        if (!\is_array($claims)) {
            throw DpopException::because('proof payload is not a JSON object');
        }

        $jti = $claims['jti'] ?? null;
        if (!\is_string($jti) || '' === $jti || \strlen($jti) > 256) {
            throw DpopException::because('jti claim is missing or invalid');
        }

        if (($claims['htm'] ?? null) !== strtoupper($httpMethod)) {
            throw DpopException::because('htm does not match the request method');
        }

        $htu = $claims['htu'] ?? null;
        if (!\is_string($htu) || HtuNormalizer::normalize($htu) !== HtuNormalizer::normalize($httpUri)) {
            throw DpopException::because('htu does not match the request URI');
        }

        $iat = $claims['iat'] ?? null;
        $now = $this->clock->now()->getTimestamp();
        if (!\is_int($iat) || $iat > $now + $this->leewaySeconds || $iat < $now - $this->maxAgeSeconds) {
            throw DpopException::because('iat is missing or outside the accepted window');
        }

        $ath = $claims['ath'] ?? null;
        if (null !== $accessToken) {
            if (!\is_string($ath) || !hash_equals(self::accessTokenHash($accessToken), $ath)) {
                throw DpopException::because('ath does not match the access token');
            }
        }

        $nonce = $claims['nonce'] ?? null;
        if (null !== $expectedNonce && (!\is_string($nonce) || !hash_equals($expectedNonce, $nonce))) {
            throw DpopException::because('nonce is missing or invalid');
        }

        $jkt = $jwk->thumbprint('sha256');
        if (null !== $expectedJkt && !hash_equals($expectedJkt, $jkt)) {
            throw DpopException::because('proof key does not match the key bound to the access token');
        }

        // Replay protection last: only proofs that are otherwise valid consume a jti slot.
        $expiresAt = (new \DateTimeImmutable('@'.$iat))->modify(\sprintf('+%d seconds', $this->maxAgeSeconds + $this->leewaySeconds));
        if (!$this->replayStore->remember($jkt.'|'.$jti, $expiresAt)) {
            throw DpopException::because('proof has already been used');
        }

        return new DpopProof(
            jkt: $jkt,
            jti: $jti,
            htm: $claims['htm'],
            htu: $htu,
            iat: $iat,
            publicJwk: $jwkValues,
            ath: \is_string($ath) ? $ath : null,
            nonce: \is_string($nonce) ? $nonce : null,
        );
    }

    /**
     * base64url(SHA-256(access token)) - the "ath" claim value.
     */
    public static function accessTokenHash(string $accessToken): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $accessToken, true)), '+/', '-_'), '=');
    }

    private function parse(string $proof): JWS
    {
        try {
            $jws = $this->serializer->unserialize($proof);
        } catch (\Throwable) {
            throw DpopException::because('proof is not a compact JWS');
        }

        if (1 !== $jws->countSignatures() || $jws->isPayloadDetached()) {
            throw DpopException::because('proof is not a compact JWS');
        }

        return $jws;
    }
}
