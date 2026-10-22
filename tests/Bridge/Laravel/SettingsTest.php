<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Bridge\Laravel;

use GuillaumeTissier\ResourceGuard\Bridge\Laravel\Settings;
use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\TestCase;

final class SettingsTest extends TestCase
{
    public function testEnvironmentStringsAreNormalized(): void
    {
        $settings = Settings::fromConfig($this->config([
            'jwks_uri' => ' http://auth-server/.well-known/jwks.json ',
            'public_key_path' => '',
            'allowed_clients' => 'my-spa, admin-app,,',
            'require_dpop' => 'false',
            'leeway' => '45',
            'dpop_max_age' => 'not a number',
            'cache_store' => 'redis',
            'user_model' => null,
            'webhook' => ['secret' => str_repeat('s', 32), 'path' => '/hook', 'tolerance' => 60],
        ]));

        self::assertSame('http://auth-server/.well-known/jwks.json', $settings->jwksUri);
        self::assertNull($settings->publicKeyPath, 'empty string means not set');
        self::assertSame(['my-spa', 'admin-app'], $settings->allowedClients);
        self::assertFalse($settings->requireDpop);
        self::assertSame(45, $settings->leeway);
        self::assertSame(300, $settings->dpopMaxAge, 'invalid values fall back to the default');
        self::assertSame('redis', $settings->cacheStore);
        self::assertNull($settings->userModel);
        self::assertSame('/hook', $settings->webhookPath);
        self::assertSame(60, $settings->webhookTolerance);
    }

    public function testPublishedConfigWithRealTypes(): void
    {
        $settings = Settings::fromConfig($this->config([
            'public_key_path' => '/keys/public.pem',
            'allowed_clients' => ['my-spa'],
            'require_dpop' => true,
        ]));

        self::assertNull($settings->jwksUri, 'optional when a public key is configured');
        self::assertSame('/keys/public.pem', $settings->publicKeyPath);
        self::assertSame(['my-spa'], $settings->allowedClients);
        self::assertTrue($settings->requireDpop);
        self::assertSame('', $settings->webhookSecret);
        self::assertNull($settings->webhookPath);
    }

    /**
     * @param array<string, mixed> $values the "resource-guard" section
     */
    private function config(array $values): Repository
    {
        return new class(['resource-guard' => $values]) implements Repository {
            /**
             * @param array<string, mixed> $items
             */
            public function __construct(private array $items)
            {
            }

            public function has($key): bool
            {
                return null !== $this->get($key);
            }

            /**
             * @param array<array-key, mixed>|string $key
             */
            public function get($key, $default = null): mixed
            {
                if (!\is_string($key)) {
                    return $default;
                }
                $value = $this->items;
                foreach (explode('.', $key) as $segment) {
                    if (!\is_array($value) || !\array_key_exists($segment, $value)) {
                        return $default;
                    }
                    $value = $value[$segment];
                }

                return $value;
            }

            /**
             * @return array<string, mixed>
             */
            public function all(): array
            {
                return $this->items;
            }

            /**
             * @param array<array-key, mixed>|string $key
             */
            public function set($key, $value = null): void
            {
            }

            public function prepend($key, $value): void
            {
            }

            public function push($key, $value): void
            {
            }
        };
    }
}
