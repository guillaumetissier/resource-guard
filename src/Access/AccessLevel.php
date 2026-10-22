<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Access;

/**
 * Access levels, ordered: each level includes the ones below it (MANAGE > WRITE > READ > NONE).
 * The backing value is the short code used in access expressions ("vehicle:w").
 */
enum AccessLevel: string
{
    case None = '-';
    case Read = 'r';
    case Write = 'w';
    case Manage = 'm';

    public function rank(): int
    {
        return match ($this) {
            self::None => 0,
            self::Read => 1,
            self::Write => 2,
            self::Manage => 3,
        };
    }

    /**
     * True when this level grants at least $required.
     */
    public function includes(self $required): bool
    {
        return $this->rank() >= $required->rank();
    }

    public static function max(self ...$levels): self
    {
        $max = self::None;
        foreach ($levels as $level) {
            if ($level->rank() > $max->rank()) {
                $max = $level;
            }
        }

        return $max;
    }

    public static function min(self $a, self $b): self
    {
        return $a->rank() <= $b->rank() ? $a : $b;
    }

    public function label(): string
    {
        return match ($this) {
            self::None => 'none',
            self::Read => 'read',
            self::Write => 'write',
            self::Manage => 'manage',
        };
    }
}
