<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

use GuillaumeTissier\ResourceGuard\Util\Json;

/**
 * A verified access token issued by the auth server.
 */
final readonly class AccessToken
{
    /**
     * @param list<string>         $scopes
     * @param array<string, mixed> $claims all claims, for application-specific needs
     */
    public function __construct(
        public string $id,
        public string $subject,
        public string $clientId,
        public array $scopes,
        public \DateTimeImmutable $expiresAt,
        public ?string $jkt,
        public array $claims,
        public string $raw,
    ) {
    }

    public function isDpopBound(): bool
    {
        return null !== $this->jkt;
    }

    public function hasScope(string $scope): bool
    {
        return \in_array($scope, $this->scopes, true);
    }

    /**
     * Who is really acting when an administrator impersonates the subject (RFC 8693 "act" claim).
     */
    public function actorId(): ?string
    {
        $actor = Json::object($this->claims['act'] ?? null)['sub'] ?? null;

        return \is_string($actor) && '' !== $actor ? $actor : null;
    }

    public function impersonationId(): ?string
    {
        $id = $this->claims['imp'] ?? null;

        return \is_string($id) ? $id : null;
    }

    /**
     * Impersonation::MODE_READ_ONLY or Impersonation::MODE_FULL, null when not impersonated.
     */
    public function impersonationMode(): ?string
    {
        if (null === $this->actorId()) {
            return null;
        }

        // Unknown or missing mode on an impersonation token: fail safe.
        return ($this->claims['imp_mode'] ?? null) === Impersonation::MODE_FULL ? Impersonation::MODE_FULL : Impersonation::MODE_READ_ONLY;
    }
}
