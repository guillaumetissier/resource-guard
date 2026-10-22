<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Guard;

use GuillaumeTissier\ResourceGuard\Token\AccessToken;
use GuillaumeTissier\ResourceGuard\Token\Impersonation;

/**
 * The authenticated caller of a protected resource.
 */
final readonly class Principal
{
    public function __construct(
        /** Identifier of the user in the main application database (the token "sub"). */
        public string $userId,
        public string $clientId,
        /** @var list<string> */
        public array $scopes,
        public AccessToken $token,
        /** True when the request carried a valid DPoP proof for a DPoP-bound token. */
        public bool $proofOfPossession,
    ) {
    }

    public function hasScope(string $scope): bool
    {
        return \in_array($scope, $this->scopes, true);
    }

    /**
     * True when an administrator acts on behalf of $userId.
     */
    public function isImpersonated(): bool
    {
        return null !== $this->token->actorId();
    }

    /**
     * Id (in the main application) of the administrator acting on behalf of the user, if any.
     * Record it in audit trails: "changed by <actorId> on behalf of <userId>".
     */
    public function actorId(): ?string
    {
        return $this->token->actorId();
    }

    public function isReadOnly(): bool
    {
        return Impersonation::MODE_READ_ONLY === $this->token->impersonationMode();
    }
}
