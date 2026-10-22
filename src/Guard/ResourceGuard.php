<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Guard;

use GuillaumeTissier\ResourceGuard\Dpop\DpopException;
use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use GuillaumeTissier\ResourceGuard\Token\AccessTokenValidator;
use GuillaumeTissier\ResourceGuard\Token\InvalidTokenException;

/**
 * Framework-agnostic entry point: turns the Authorization / DPoP headers of a request
 * into a Principal, or fails with an AuthenticationFailed carrying the right challenge.
 *
 * Rules (RFC 6750 + RFC 9449 section 7):
 *  - "Authorization: DPoP <token>" requires a valid proof signed by the key bound to the token (cnf.jkt);
 *  - a DPoP-bound token presented with the "Bearer" scheme is rejected (otherwise binding would be pointless);
 *  - plain Bearer tokens are accepted only when $requireDpop is false;
 *  - during a read-only impersonation, only safe methods (GET, HEAD, OPTIONS) are allowed.
 */
final readonly class ResourceGuard
{
    public function __construct(
        private AccessTokenValidator $tokenValidator,
        private DpopProofValidator $dpopValidator,
        private bool $requireDpop = true,
        private bool $enforceReadOnlyImpersonation = true,
    ) {
    }

    /**
     * @param string       $method              HTTP method of the request
     * @param string       $uri                 absolute URI of the request (scheme://host/path)
     * @param string|null  $authorizationHeader raw "Authorization" header
     * @param list<string> $dpopHeaders         every "DPoP" header value of the request
     *
     * @throws AuthenticationFailed
     */
    public function authenticate(string $method, string $uri, ?string $authorizationHeader, array $dpopHeaders = []): Principal
    {
        $principal = $this->authenticateToken($method, $uri, $authorizationHeader, $dpopHeaders);

        if ($this->enforceReadOnlyImpersonation && $principal->isReadOnly()
            && !\in_array(strtoupper($method), ['GET', 'HEAD', 'OPTIONS'], true)) {
            throw AuthenticationFailed::forbidden('impersonation_read_only', 'Read-only impersonation: write requests are not allowed');
        }

        return $principal;
    }

    /**
     * @param list<string> $dpopHeaders
     */
    private function authenticateToken(string $method, string $uri, ?string $authorizationHeader, array $dpopHeaders): Principal
    {
        if (null === $authorizationHeader || '' === trim($authorizationHeader)) {
            throw AuthenticationFailed::missingCredentials($this->requireDpop);
        }

        if (!preg_match('/^(DPoP|Bearer)\s+([A-Za-z0-9\-._~+\/]+=*)$/i', trim($authorizationHeader), $m)) {
            throw AuthenticationFailed::invalidToken('Malformed Authorization header', $this->requireDpop);
        }
        $scheme = strtolower($m[1]);
        $rawToken = $m[2];

        try {
            $token = $this->tokenValidator->validate($rawToken);
        } catch (InvalidTokenException $e) {
            throw AuthenticationFailed::invalidToken($e->getMessage(), 'dpop' === $scheme || $this->requireDpop);
        }

        if ('bearer' === $scheme) {
            if ($token->isDpopBound()) {
                throw AuthenticationFailed::invalidToken('DPoP-bound token presented as a Bearer token', true);
            }
            if ($this->requireDpop) {
                throw AuthenticationFailed::invalidToken('DPoP-bound token required', true);
            }

            return new Principal($token->subject, $token->clientId, $token->scopes, $token, false);
        }

        if (!$token->isDpopBound()) {
            throw AuthenticationFailed::invalidToken('Token is not DPoP-bound', true);
        }

        if (1 !== \count($dpopHeaders)) {
            throw AuthenticationFailed::invalidDpopProof('Exactly one DPoP header is required');
        }

        try {
            $this->dpopValidator->validate(
                proof: $dpopHeaders[0],
                httpMethod: $method,
                httpUri: $uri,
                accessToken: $rawToken,
                expectedJkt: $token->jkt,
            );
        } catch (DpopException $e) {
            throw AuthenticationFailed::invalidDpopProof($e->getMessage());
        }

        return new Principal($token->subject, $token->clientId, $token->scopes, $token, true);
    }
}
