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
use Illuminate\Contracts\Config\Repository as Config;
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

        $this->app->singleton(Settings::class, static fn (Application $app): Settings => Settings::fromConfig($app->make(Config::class)));

        $this->app->singleton(JwksProviderInterface::class, static function (Application $app): JwksProviderInterface {
            $settings = $app->make(Settings::class);
            if (null !== $settings->publicKeyPath) {
                return StaticJwksProvider::fromPublicKeyFile($settings->publicKeyPath);
            }
            if (null === $settings->jwksUri) {
                throw new \LogicException('Set resource-guard.jwks_uri (AUTH_SERVER_JWKS_URI) or resource-guard.public_key_path.');
            }

            // Guzzle ships with every Laravel application and implements PSR-18 / PSR-17.
            return new HttpJwksProvider(
                $settings->jwksUri,
                new \GuzzleHttp\Client(['timeout' => 5]),
                new \GuzzleHttp\Psr7\HttpFactory(),
                $app->make(CacheFactory::class)->store($settings->cacheStore),
            );
        });

        $this->app->singleton(AccessTokenValidator::class, static fn (Application $app): AccessTokenValidator => new AccessTokenValidator(
            $app->make(JwksProviderInterface::class),
            $app->make(Settings::class)->allowedClients,
            null,
            $app->make(Settings::class)->leeway,
        ));

        $this->app->singleton(DpopProofValidator::class, static fn (Application $app): DpopProofValidator => new DpopProofValidator(
            new Psr16ReplayStore($app->make(CacheFactory::class)->store($app->make(Settings::class)->cacheStore)),
            null,
            $app->make(Settings::class)->dpopMaxAge,
            $app->make(Settings::class)->leeway,
        ));

        $this->app->singleton(ResourceGuard::class, static fn (Application $app): ResourceGuard => new ResourceGuard(
            $app->make(AccessTokenValidator::class),
            $app->make(DpopProofValidator::class),
            $app->make(Settings::class)->requireDpop,
        ));

        $this->app->singleton(WebhookSignature::class, static fn (Application $app): WebhookSignature => new WebhookSignature(
            $app->make(Settings::class)->webhookSecret,
            $app->make(Settings::class)->webhookTolerance,
        ));
    }

    public function boot(Router $router): void
    {
        $this->publishes([
            __DIR__.'/../../../config/resource-guard.php' => $this->app->configPath('resource-guard.php'),
        ], 'resource-guard-config');

        $router->aliasMiddleware('auth.oauth', AuthenticateWithAuthServer::class);

        $path = $this->app->make(Settings::class)->webhookPath;
        // routesAreCached() belongs to the full application, not to the Application contract.
        $routesCached = method_exists($this->app, 'routesAreCached') && $this->app->routesAreCached();
        if (null !== $path && !$routesCached) {
            $router->post($path, WebhookController::class)->name('resource-guard.webhook');
        }
    }
}
