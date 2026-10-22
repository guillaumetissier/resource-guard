<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Laravel;

use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use GuillaumeTissier\ResourceGuard\Dpop\Psr16ReplayStore;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use GuillaumeTissier\ResourceGuard\Token\AccessTokenValidator;
use GuillaumeTissier\ResourceGuard\Token\HttpJwksProvider;
use GuillaumeTissier\ResourceGuard\Token\JwksProviderInterface;
use GuillaumeTissier\ResourceGuard\Token\StaticJwksProvider;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookSignature;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

/**
 * Laravel integration. Auto-discovered via composer.json "extra.laravel".
 *
 * Provides:
 *  - the "auth.oauth" route middleware (optionally with scopes: "auth.oauth:orders.read,orders.write");
 *  - the webhook endpoint dispatching an AuthServerEventReceived Laravel event per verified delivery.
 */
final class ResourceGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../../config/resource-guard.php', 'resource-guard');

        $this->app->singleton(JwksProviderInterface::class, function (Application $app): JwksProviderInterface {
            $config = $app['config']['resource-guard'];

            if (!empty($config['public_key_path'])) {
                return StaticJwksProvider::fromPublicKeyFile($config['public_key_path']);
            }

            // Guzzle ships with every Laravel application and implements PSR-18 / PSR-17.
            return new HttpJwksProvider(
                $config['jwks_uri'],
                new \GuzzleHttp\Client(['timeout' => 5]),
                new \GuzzleHttp\Psr7\HttpFactory(),
                $app->make(CacheFactory::class)->store($config['cache_store']),
            );
        });

        $this->app->singleton(AccessTokenValidator::class, fn (Application $app) => new AccessTokenValidator(
            $app->make(JwksProviderInterface::class),
            array_values($app['config']['resource-guard.allowed_clients']),
            null,
            (int) $app['config']['resource-guard.leeway'],
        ));

        $this->app->singleton(DpopProofValidator::class, fn (Application $app) => new DpopProofValidator(
            new Psr16ReplayStore($app->make(CacheFactory::class)->store($app['config']['resource-guard.cache_store'])),
            null,
            (int) $app['config']['resource-guard.dpop_max_age'],
            (int) $app['config']['resource-guard.leeway'],
        ));

        $this->app->singleton(ResourceGuard::class, fn (Application $app) => new ResourceGuard(
            $app->make(AccessTokenValidator::class),
            $app->make(DpopProofValidator::class),
            (bool) $app['config']['resource-guard.require_dpop'],
        ));

        $this->app->singleton(WebhookSignature::class, fn (Application $app) => new WebhookSignature(
            (string) $app['config']['resource-guard.webhook.secret'],
            (int) $app['config']['resource-guard.webhook.tolerance'],
        ));
    }

    public function boot(Router $router): void
    {
        $this->publishes([
            __DIR__.'/../../../config/resource-guard.php' => $this->app->configPath('resource-guard.php'),
        ], 'resource-guard-config');

        $router->aliasMiddleware('auth.oauth', AuthenticateWithAuthServer::class);

        $path = $this->app['config']['resource-guard.webhook.path'];
        if (\is_string($path) && '' !== $path && !$this->app->routesAreCached()) {
            $router->post($path, WebhookController::class)->name('resource-guard.webhook');
        }
    }
}
