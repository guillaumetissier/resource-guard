<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Guard;

use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;

/**
 * Authentication failure, carrying what is needed for an RFC 6750 / RFC 9449 compliant 401 response.
 */
final class AuthenticationFailed extends \RuntimeException
{
    private function __construct(
        string $description,
        public readonly string $errorCode,
        public readonly bool $dpopChallenge,
        public readonly int $statusCode = 401,
    ) {
        parent::__construct($description);
    }

    public static function missingCredentials(bool $requireDpop): self
    {
        // RFC 6750 section 3.1: no error code when the request carried no credentials.
        return new self('Authentication required', '', $requireDpop);
    }

    public static function invalidToken(string $description, bool $dpopChallenge): self
    {
        return new self($description, 'invalid_token', $dpopChallenge);
    }

    public static function invalidDpopProof(string $description): self
    {
        return new self($description, 'invalid_dpop_proof', true);
    }

    /**
     * Authenticated, but the request is not allowed (HTTP 403), e.g. a write during a read-only impersonation.
     */
    public static function forbidden(string $errorCode, string $description): self
    {
        return new self($description, $errorCode, false, 403);
    }

    /**
     * Value of the WWW-Authenticate header for the 401 response.
     */
    public function wwwAuthenticate(): string
    {
        $params = [];
        if ('' !== $this->errorCode) {
            $params[] = \sprintf('error="%s"', $this->errorCode);
            $params[] = \sprintf('error_description="%s"', addcslashes($this->getMessage(), '"\\'));
        }

        if ($this->dpopChallenge) {
            $params[] = \sprintf('algs="%s"', implode(' ', DpopProofValidator::SUPPORTED_ALGORITHMS));

            return 'DPoP'.([] !== $params ? ' '.implode(', ', $params) : '');
        }

        return 'Bearer'.([] !== $params ? ' '.implode(', ', $params) : '');
    }

    /**
     * @return array{error: string, error_description: string}
     */
    public function toArray(): array
    {
        return [
            'error' => '' !== $this->errorCode ? $this->errorCode : 'unauthorized',
            'error_description' => $this->getMessage(),
        ];
    }
}
