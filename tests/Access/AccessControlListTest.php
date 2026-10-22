<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Access;

use GuillaumeTissier\ResourceGuard\Access\AccessControlList;
use GuillaumeTissier\ResourceGuard\Access\AccessLevel;
use PHPUnit\Framework\TestCase;

/**
 * Domain tree used here: a1 > a10 > (a100, a101), and a1 > a11 (sibling of a10).
 */
final class AccessControlListTest extends TestCase
{
    private function acl(): AccessControlList
    {
        return AccessControlList::fromClaims([
            'dom' => '/a1/a10/',
            'acl' => [
                ['/a1/a10/', true, '*:r user:w:own'],
                ['/a1/a10/a100/', false, 'vehicle:w'],
                // Outside the user's subtree: must never apply, whatever it says.
                ['/a1/', true, '*:m'],
            ],
        ]);
    }

    public function testSubdomainsInheritWhenRequested(): void
    {
        self::assertSame(AccessLevel::Read, $this->acl()->levelFor('vehicle', '/a1/a10/a101/'));
    }

    public function testEntryWithoutSubdomainsAppliesToItsDomainOnly(): void
    {
        self::assertSame(AccessLevel::Write, $this->acl()->levelFor('vehicle', '/a1/a10/a100/'));
        self::assertSame(AccessLevel::Read, $this->acl()->levelFor('vehicle', '/a1/a10/a100/x/'));
    }

    public function testParentAndSiblingDomainsAreOutOfReach(): void
    {
        self::assertSame(AccessLevel::None, $this->acl()->levelFor('vehicle', '/a1/'));
        self::assertSame(AccessLevel::None, $this->acl()->levelFor('vehicle', '/a1/a11/'));
    }

    public function testPathsAreNormalized(): void
    {
        self::assertTrue($this->acl()->allows('vehicle', AccessLevel::Write, 'a1/a10/a100'));
        // "/a1/a1000/" is not inside "/a1/a10/" even though the strings share a prefix.
        self::assertSame(AccessLevel::None, $this->acl()->levelFor('vehicle', '/a1/a1000/'));
    }

    public function testOwnResources(): void
    {
        self::assertSame(AccessLevel::Read, $this->acl()->levelFor('user', '/a1/a10/'));
        self::assertSame(AccessLevel::Write, $this->acl()->levelFor('user', '/a1/a10/', own: true));
    }

    public function testMalformedClaimsGrantNothing(): void
    {
        $acl = AccessControlList::fromClaims(['dom' => '/a1/', 'acl' => [['/a1/', 'yes', '*:m'], ['/a1/', true, 'vehicle:zz'], 'junk']]);

        self::assertSame([], $acl->entries);
        self::assertSame(AccessLevel::None, $acl->levelFor('vehicle', '/a1/'));
    }

    public function testRoundTripThroughClaims(): void
    {
        $claims = $this->acl()->toClaims();

        self::assertSame('/a1/a10/', $claims['dom'] ?? null);
        self::assertEquals($this->acl(), AccessControlList::fromClaims($claims));
    }
}
