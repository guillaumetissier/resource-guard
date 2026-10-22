<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Util;

/**
 * @internal
 */
final class Json
{
    private function __construct()
    {
    }

    /**
     * A decoded JSON object as an array with string keys, or null when $value is not one.
     *
     * @return array<string, mixed>|null
     */
    public static function object(mixed $value): ?array
    {
        if (!\is_array($value)) {
            return null;
        }
        $object = [];
        foreach ($value as $key => $item) {
            if (!\is_string($key)) {
                return null; // a JSON list, not an object ([] stays an empty object: no key to check)
            }
            $object[$key] = $item;
        }

        return $object;
    }
}
