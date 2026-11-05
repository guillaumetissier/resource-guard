<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Access;

/**
 * A compact set of access rules, e.g. "*:w tire:r invoice:- user:w:own @access:w".
 *
 * Grammar: rules separated by spaces (or commas), each "<type>:<level>[:own]" where
 *  - <type>  is "*" (every regular type), a resource type ("vehicle"), a facet of a resource type
 *            ("vehicle.pricing": a part of the resource, e.g. its prices) or a reserved system type
 *            starting with "@" ("@access", "@impersonate");
 *  - <level> is "-" (none), "r" (read), "w" (write) or "m" (manage); levels include the lower ones.
 *            Facets take "-", "r" or "w" only: creating and deleting concern the whole resource;
 *  - ":own"  limits the rule to resources owned by the user (his own profile, his drafts...).
 *
 * Evaluation, for a type and "own resource or not":
 *  - within each scope (general rules, ":own" rules), the most specific rule wins, whatever the
 *    order: facet, then its type, then the wildcard. "*:w tire:r" caps tires at read,
 *    "vehicle:w vehicle.pricing:r" lets the user change everything but the prices;
 *  - a facet rule of level read or more also grants read on its type: "vehicle.pricing:w" alone lets
 *    the user see the vehicles whose prices he changes;
 *  - "*" never covers reserved "@" types: system powers must always be granted explicitly;
 *  - for an owned resource, the result is the higher of the general level and the ":own" level,
 *    so "*:r user:w:own" reads everything and writes the user's own profile.
 */
final readonly class AccessExpression
{
    public const WILDCARD = '*';
    public const FACET_SEPARATOR = '.';
    private const TYPE_PATTERN = '/^(\*|@[a-z][a-z0-9_\-]*|[a-z][a-z0-9_\-]*(\.[a-z][a-z0-9_\-]*)?)$/';

    /**
     * @param array<string, array{all?: AccessLevel, own?: AccessLevel}> $rules keyed by type
     */
    private function __construct(private array $rules)
    {
    }

    public static function parse(string $expression): self
    {
        $rules = [];
        foreach (preg_split('/[\s,]+/', trim($expression), -1, \PREG_SPLIT_NO_EMPTY) ?: [] as $token) {
            $parts = explode(':', $token);
            if (\count($parts) < 2 || \count($parts) > 3) {
                throw new InvalidAccessExpression(\sprintf('"%s": expected <type>:<level>[:own].', $token));
            }
            [$type, $code] = $parts;
            $type = strtolower($type);
            if (1 !== preg_match(self::TYPE_PATTERN, $type)) {
                throw new InvalidAccessExpression(\sprintf('"%s": invalid resource type "%s".', $token, $type));
            }
            $level = AccessLevel::tryFrom(strtolower($code))
                ?? throw new InvalidAccessExpression(\sprintf('"%s": unknown level "%s" (use -, r, w or m).', $token, $code));
            if (AccessLevel::Manage === $level && null !== self::parentType($type)) {
                throw new InvalidAccessExpression(\sprintf('"%s": a facet takes -, r or w (manage concerns the whole resource).', $token));
            }
            if (isset($parts[2]) && 'own' !== strtolower($parts[2])) {
                throw new InvalidAccessExpression(\sprintf('"%s": the only qualifier is ":own".', $token));
            }
            $scope = isset($parts[2]) ? 'own' : 'all';
            if (isset($rules[$type][$scope])) {
                throw new InvalidAccessExpression(\sprintf('"%s": %s is defined twice.', $token, $type.('own' === $scope ? ':own' : '')));
            }
            $rules[$type][$scope] = $level;
        }

        return new self($rules);
    }

    public static function empty(): self
    {
        return new self([]);
    }

    public function levelFor(string $type, bool $own = false): AccessLevel
    {
        $type = strtolower($type);
        $level = $this->scopeLevel($type, 'all');

        return $own ? AccessLevel::max($level, $this->scopeLevel($type, 'own')) : $level;
    }

    /**
     * Type of a facet ("vehicle" for "vehicle.pricing"), null for anything else.
     */
    public static function parentType(string $type): ?string
    {
        $position = strpos($type, self::FACET_SEPARATOR);

        return false === $position || self::isReserved($type) ? null : substr($type, 0, $position);
    }

    private function scopeLevel(string $type, string $scope): AccessLevel
    {
        $level = $this->ruleFor($type, $scope) ?? AccessLevel::None;
        if (null === self::parentType($type) && !self::isReserved($type) && self::WILDCARD !== $type) {
            // A right on one of its facets lets the user see the resource itself.
            foreach ($this->rules as $named => $scopes) {
                if (self::parentType($named) === $type && ($scopes[$scope] ?? AccessLevel::None)->includes(AccessLevel::Read)) {
                    return AccessLevel::max($level, AccessLevel::Read);
                }
            }
        }

        return $level;
    }

    private function ruleFor(string $type, string $scope): ?AccessLevel
    {
        if (isset($this->rules[$type][$scope])) {
            return $this->rules[$type][$scope];
        }
        $parent = self::parentType($type);
        if (null !== $parent && isset($this->rules[$parent][$scope])) {
            return $this->rules[$parent][$scope];
        }

        return self::isReserved($type) ? null : ($this->rules[self::WILDCARD][$scope] ?? null);
    }

    public function allows(string $type, AccessLevel $required, bool $own = false): bool
    {
        return $this->levelFor($type, $own)->includes($required);
    }

    /**
     * Types and facets named explicitly (the wildcard excluded).
     *
     * @return list<string>
     */
    public function namedTypes(): array
    {
        return array_values(array_filter(array_keys($this->rules), static fn (string $t): bool => self::WILDCARD !== $t));
    }

    /**
     * True when this expression never grants more than $bound, for every type and scope:
     * a user may only delegate rights he holds himself.
     */
    public function isWithin(self $bound): bool
    {
        // Names no expression can use stand for "any type not named in either expression" and, for
        // each named type, "any of its facets not named in either expression".
        $named = [...$this->namedTypes(), ...$bound->namedTypes()];
        $types = ['~other'];
        foreach ($named as $type) {
            $base = self::parentType($type) ?? $type;
            array_push($types, $type, $base);
            if (!self::isReserved($base)) {
                $types[] = $base.self::FACET_SEPARATOR.'~other';
            }
        }
        $types = array_unique($types);
        foreach ($types as $type) {
            foreach ([false, true] as $own) {
                if ($this->levelFor($type, $own)->rank() > $bound->levelFor($type, $own)->rank()) {
                    return false;
                }
            }
        }

        return true;
    }

    public static function isReserved(string $type): bool
    {
        return str_starts_with($type, '@');
    }

    public function isEmpty(): bool
    {
        return [] === $this->rules;
    }

    /**
     * Canonical form: wildcard first, then regular types, then reserved types, alphabetically.
     */
    public function toString(): string
    {
        $types = array_keys($this->rules);
        usort($types, static fn (string $a, string $b): int => [self::WILDCARD !== $a, self::isReserved($a), $a] <=> [self::WILDCARD !== $b, self::isReserved($b), $b]);

        $tokens = [];
        foreach ($types as $type) {
            foreach (['all' => '', 'own' => ':own'] as $scope => $suffix) {
                if (isset($this->rules[$type][$scope])) {
                    $tokens[] = $type.':'.$this->rules[$type][$scope]->value.$suffix;
                }
            }
        }

        return implode(' ', $tokens);
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
