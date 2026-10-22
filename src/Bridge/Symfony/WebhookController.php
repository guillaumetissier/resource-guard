<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Symfony;

use GuillaumeTissier\ResourceGuard\Webhook\WebhookEvent;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookSignature;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Receives the auth server webhooks and dispatches an AuthServerEventReceived event.
 * Register it as a controller on a route excluded from any firewall authentication.
 */
final readonly class WebhookController
{
    public function __construct(
        private WebhookSignature $signature,
        private EventDispatcherInterface $dispatcher,
        private CacheInterface $cache,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $payload = $request->getContent();

        if (!$this->signature->verify($payload, $request->headers->get(WebhookSignature::HEADER))) {
            return new Response('', Response::HTTP_UNAUTHORIZED);
        }

        try {
            $event = WebhookEvent::fromJson($payload);
        } catch (\Throwable) {
            return new Response('', Response::HTTP_BAD_REQUEST);
        }

        // Deliveries can be retried: process each event id once.
        $key = 'resource_guard_webhook_'.hash('sha256', $event->id);
        if ($this->cache->has($key)) {
            return new Response('', Response::HTTP_NO_CONTENT);
        }
        $this->cache->set($key, 1, 86400);

        $this->dispatcher->dispatch(new AuthServerEventReceived($event));

        return new Response('', Response::HTTP_NO_CONTENT);
    }
}
