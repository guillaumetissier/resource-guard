<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Laravel;

use GuillaumeTissier\ResourceGuard\Webhook\WebhookEvent;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookSignature;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Receives the auth server webhooks and re-dispatches them as Laravel events:
 *
 *   Event::listen(AuthServerEventReceived::class, function (AuthServerEventReceived $e) {
 *       if ($e->event->type === WebhookEvent::USER_LOCKED) { ... }
 *   });
 */
final readonly class WebhookController
{
    public function __construct(
        private WebhookSignature $signature,
        private Dispatcher $events,
        private CacheFactory $cache,
        private Settings $settings,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $payload = $request->getContent();

        if (!$this->signature->verify($payload, $request->headers->get(WebhookSignature::HEADER))) {
            return new Response('', 401);
        }

        try {
            $event = WebhookEvent::fromJson($payload);
        } catch (\Throwable) {
            return new Response('', 400);
        }

        // Deliveries can be retried: process each event id once.
        $store = $this->cache->store($this->settings->cacheStore);
        if (!$store->add('resource_guard_webhook_'.$event->id, 1, 86400)) {
            return new Response('', 204);
        }

        $this->events->dispatch(new AuthServerEventReceived($event));

        return new Response('', 204);
    }
}
