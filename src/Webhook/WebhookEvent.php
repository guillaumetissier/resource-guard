<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Webhook;

use GuillaumeTissier\ResourceGuard\Util\Json;

/**
 * A verified event received from the auth server.
 */
final readonly class WebhookEvent
{
    public const USER_CREATED = 'user.created';
    public const USER_LOGIN_SUCCEEDED = 'user.login_succeeded';
    public const USER_LOGIN_FAILED = 'user.login_failed';
    public const USER_LOCKED = 'user.locked';
    public const USER_TWO_FACTOR_ENABLED = 'user.two_factor_enabled';
    public const USER_TWO_FACTOR_DISABLED = 'user.two_factor_disabled';
    /** Grace period: the user chose "Later" on the enrollment page. data: postpone_count, deadline */
    public const USER_TWO_FACTOR_POSTPONED = 'user.two_factor_postponed';
    public const USER_PASSWORD_CHANGED = 'user.password_changed';
    public const USER_ROLES_CHANGED = 'user.roles_changed';
    /**
     * The user's rights changed (grant added, changed or removed, domain changed, domain ownership changed).
     * Takes effect in his next access token; data: change, domain, actor_id. Refetch or drop cached rights.
     */
    public const USER_ACCESS_CHANGED = 'user.access_changed';
    /** data: user_id (impersonated user), actor_id (administrator), mode, reason, expires_at, impersonation_id */
    public const IMPERSONATION_STARTED = 'impersonation.started';
    public const IMPERSONATION_ENDED = 'impersonation.ended';

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        public string $id,
        public string $type,
        public \DateTimeImmutable $occurredAt,
        public array $data,
    ) {
    }

    /**
     * Identifier of the user in the main application database, when the event concerns a user.
     */
    public function userId(): ?string
    {
        $id = $this->data['user_id'] ?? null;

        return \is_string($id) ? $id : null;
    }

    public static function fromJson(string $json): self
    {
        $d = json_decode($json, true, 16, \JSON_THROW_ON_ERROR);
        if (!\is_array($d) || !\is_string($d['id'] ?? null) || !\is_string($d['type'] ?? null) || !\is_string($d['occurred_at'] ?? null)) {
            throw new \InvalidArgumentException('Malformed webhook payload');
        }

        return new self($d['id'], $d['type'], new \DateTimeImmutable($d['occurred_at']), Json::object($d['data'] ?? null) ?? []);
    }

    public function toJson(): string
    {
        return json_encode([
            'id' => $this->id,
            'type' => $this->type,
            'occurred_at' => $this->occurredAt->format(\DATE_ATOM),
            'data' => $this->data,
        ], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
    }
}
