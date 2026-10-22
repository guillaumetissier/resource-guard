<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Guard;

use GuillaumeTissier\ResourceGuard\Access\AccessControlList;
use GuillaumeTissier\ResourceGuard\Access\AccessLevel;
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

    /**
     * The user's rights by domain, from the "dom" and "acl" claims.
     */
    public function acl(): AccessControlList
    {
        return AccessControlList::fromClaims($this->token->claims);
    }

    /**
     * Path of the user's domain ("/a1/a10/"), null when the user belongs to no domain.
     */
    public function domain(): ?string
    {
        return $this->acl()->userDomain;
    }

    /**
     * Level the user has on a resource of $resourceType located in $domainPath.
     * Pass the id of the resource's owner to apply ":own" rules (e.g. the user's own profile).
     * During a read-only impersonation the level never exceeds READ.
     */
    public function accessLevel(string $resourceType, string $domainPath, ?string $ownerId = null): AccessLevel
    {
        $level = $this->acl()->levelFor($resourceType, $domainPath, null !== $ownerId && $ownerId === $this->userId);

        return $this->isReadOnly() ? AccessLevel::min($level, AccessLevel::Read) : $level;
    }

    /**
     * True when the user holds at least $required on a resource of $resourceType in $domainPath.
     *
     *     $principal->can('vehicle', AccessLevel::Write, $vehicle->domainPath)
     *     $principal->can('user', AccessLevel::Write, $profile->domainPath, ownerId: $profile->userId)
     */
    public function can(string $resourceType, AccessLevel $required, string $domainPath, ?string $ownerId = null): bool
    {
        return $this->accessLevel($resourceType, $domainPath, $ownerId)->includes($required);
    }
}
