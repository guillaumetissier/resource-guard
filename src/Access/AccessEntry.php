<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Access;

/**
 * Rights held on one domain, optionally extended to all its subdomains.
 */
final readonly class AccessEntry
{
    public string $domainPath;

    public function __construct(
        string $domainPath,
        public bool $includeSubdomains,
        public AccessExpression $expression,
    ) {
        $this->domainPath = DomainPath::normalize($domainPath);
    }

    public function appliesTo(string $domainPath): bool
    {
        $domainPath = DomainPath::normalize($domainPath);

        return $this->includeSubdomains ? DomainPath::isWithin($domainPath, $this->domainPath) : $domainPath === $this->domainPath;
    }

    /**
     * Token claim form: [path, includeSubdomains, expression].
     *
     * @return array{0: string, 1: bool, 2: string}
     */
    public function toClaim(): array
    {
        return [$this->domainPath, $this->includeSubdomains, $this->expression->toString()];
    }
}
