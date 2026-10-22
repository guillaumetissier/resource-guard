<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

/**
 * Impersonation modes, shared by the auth server (which issues them) and resource servers.
 */
final class Impersonation
{
    /** Granted to ROLE_ADMIN: read-only scopes, and resource servers refuse any write request. */
    public const MODE_READ_ONLY = 'read_only';

    /** Granted to ROLE_SUPER_ADMIN only: the same rights as the impersonated user. */
    public const MODE_FULL = 'full';

    private function __construct()
    {
    }
}
