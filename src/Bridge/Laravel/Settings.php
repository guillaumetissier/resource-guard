<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Laravel;

use Illuminate\Contracts\Config\Repository as Config;

/**
 * The "resource-guard" configuration, read once and normalized: environment variables arrive as
 * strings ("true", "60", "a,b"), published configs may hold real types.
 */
final readonly class Settings
{
    /**
     * @param list<string> $allowedClients
     */
    public function __construct(
        public ?string $jwksUri,
        public ?string $publicKeyPath,
        public array $allowedClients,
        public bool $requireDpop,
        public int $leeway,
        public int $dpopMaxAge,
        public ?string $cacheStore,
        public ?string $userModel,
        public string $webhookSecret,
        public ?string $webhookPath,
        public int $webhookTolerance,
    ) {
    }

    public static function fromConfig(Config $config): self
    {
        $get = static fn (string $key): mixed => $config->get('resource-guard.'.$key);

        return new self(
            jwksUri: self::string($get('jwks_uri')),
            publicKeyPath: self::string($get('public_key_path')),
            allowedClients: self::list($get('allowed_clients')),
            requireDpop: self::bool($get('require_dpop'), true),
            leeway: self::int($get('leeway'), 30),
            dpopMaxAge: self::int($get('dpop_max_age'), 300),
            cacheStore: self::string($get('cache_store')),
            userModel: self::string($get('user_model')),
            webhookSecret: self::string($get('webhook.secret')) ?? '',
            webhookPath: self::string($get('webhook.path')),
            webhookTolerance: self::int($get('webhook.tolerance'), 300),
        );
    }

    private static function string(mixed $value): ?string
    {
        return \is_string($value) && '' !== trim($value) ? trim($value) : null;
    }

    /**
     * @return list<string>
     */
    private static function list(mixed $value): array
    {
        $items = \is_string($value) ? explode(',', $value) : (\is_array($value) ? $value : []);

        return array_values(array_filter(
            array_map(static fn (mixed $item): string => \is_string($item) ? trim($item) : '', $items),
            static fn (string $item): bool => '' !== $item,
        ));
    }

    private static function bool(mixed $value, bool $default): bool
    {
        return \is_bool($value) ? $value : (filter_var($value, \FILTER_VALIDATE_BOOL, \FILTER_NULL_ON_FAILURE) ?? $default);
    }

    private static function int(mixed $value, int $default): int
    {
        $int = filter_var($value, \FILTER_VALIDATE_INT);

        return \is_int($int) ? $int : $default;
    }
}
