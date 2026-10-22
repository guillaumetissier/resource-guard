<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Token;

use Jose\Component\Core\JWKSet;

interface JwksProviderInterface
{
    /**
     * @param bool $forceRefresh bypass caches (used once when no key verifies a token, to handle key rotation)
     */
    public function getKeySet(bool $forceRefresh = false): JWKSet;
}
