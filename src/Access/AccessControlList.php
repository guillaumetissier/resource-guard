<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Access;

/**
 * Everything a user may do, by domain. Carried in access tokens as:
 *
 *   "dom": "/a1/a10/",
 *   "acl": [["/a1/a10/", true, "*:w tire:r user:w:own"], ["/a1/a10/a100/", false, "invoice:r"]]
 *
 * The level on a resource is the highest level granted by the entries covering its domain. A user
 * attached to a domain never gets any access outside that domain's subtree, and entries rooted above
 * his domain are ignored, whatever the token says.
 */
final readonly class AccessControlList
{
    /**
     * @param list<AccessEntry> $entries
     */
    public function __construct(
        /** Path of the user's domain, null for users outside any domain (platform staff). */
        public ?string $userDomain,
        public array $entries,
    ) {
    }

    public static function none(): self
    {
        return new self(null, []);
    }

    /**
     * Builds the list from token claims. Malformed entries are ignored (fail closed).
     *
     * @param array<string, mixed> $claims
     */
    public static function fromClaims(array $claims): self
    {
        $domain = \is_string($claims['dom'] ?? null) ? DomainPath::normalize($claims['dom']) : null;
        $entries = [];
        foreach (\is_array($claims['acl'] ?? null) ? $claims['acl'] : [] as $entry) {
            if (!\is_array($entry) || !\is_string($entry[0] ?? null) || !\is_bool($entry[1] ?? null) || !\is_string($entry[2] ?? null)) {
                continue;
            }
            try {
                $entries[] = new AccessEntry($entry[0], $entry[1], AccessExpression::parse($entry[2]));
            } catch (InvalidAccessExpression) {
                continue;
            }
        }

        return new self($domain, $entries);
    }

    public function levelFor(string $resourceType, string $domainPath, bool $own = false): AccessLevel
    {
        if (null !== $this->userDomain && !DomainPath::isWithin($domainPath, $this->userDomain)) {
            return AccessLevel::None;
        }

        $level = AccessLevel::None;
        foreach ($this->entries as $entry) {
            // An entry rooted above the user's domain would leak to parents: ignore it (fail closed).
            if (null !== $this->userDomain && !DomainPath::isWithin($entry->domainPath, $this->userDomain)) {
                continue;
            }
            if ($entry->appliesTo($domainPath)) {
                $level = AccessLevel::max($level, $entry->expression->levelFor($resourceType, $own));
            }
        }

        return $level;
    }

    public function allows(string $resourceType, AccessLevel $required, string $domainPath, bool $own = false): bool
    {
        return $this->levelFor($resourceType, $domainPath, $own)->includes($required);
    }

    /**
     * @return array{dom?: string, acl: list<array{0: string, 1: bool, 2: string}>}
     */
    public function toClaims(): array
    {
        $claims = ['acl' => array_map(static fn (AccessEntry $e): array => $e->toClaim(), $this->entries)];
        if (null !== $this->userDomain) {
            $claims = ['dom' => $this->userDomain] + $claims;
        }

        return $claims;
    }
}
