<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Laravel;

use GuillaumeTissier\ResourceGuard\Webhook\WebhookEvent;

/**
 * Laravel event fired for every verified webhook delivery from the auth server.
 */
final readonly class AuthServerEventReceived
{
    public function __construct(public WebhookEvent $event)
    {
    }
}
