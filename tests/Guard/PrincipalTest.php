<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Guard;

use GuillaumeTissier\ResourceGuard\Access\AccessLevel;
use GuillaumeTissier\ResourceGuard\Guard\Principal;
use GuillaumeTissier\ResourceGuard\Token\AccessToken;
use PHPUnit\Framework\TestCase;

final class PrincipalTest extends TestCase
{
    public function testFacetLevels(): void
    {
        $principal = $this->principal('vehicle.pricing:w');

        self::assertSame(AccessLevel::Write, $principal->accessLevel('vehicle.pricing', '/a1/a10/'));
        self::assertSame(AccessLevel::Read, $principal->accessLevel('vehicle', '/a1/a10/'));
        self::assertFalse($principal->can('vehicle.pricing', AccessLevel::Read, '/a1/a11/'));
    }

    public function testDeniedFacets(): void
    {
        $principal = $this->principal('vehicle:r vehicle.pricing:w');

        self::assertSame(['media', 'technical'], $principal->deniedFacets('vehicle', ['pricing', 'media', 'technical'], AccessLevel::Write, '/a1/a10/'));
        self::assertSame([], $principal->deniedFacets('vehicle', ['pricing'], AccessLevel::Write, '/a1/a10/a100/'));
        self::assertSame(['pricing'], $principal->deniedFacets('vehicle', ['pricing'], AccessLevel::Write, '/a1/a11/'));
    }

    public function testTypeRightCoversEveryFacet(): void
    {
        self::assertSame([], $this->principal('vehicle:w')->deniedFacets('vehicle', ['pricing', 'media'], AccessLevel::Write, '/a1/a10/'));
        self::assertSame(['pricing'], $this->principal('vehicle:w vehicle.pricing:r')->deniedFacets('vehicle', ['pricing', 'media'], AccessLevel::Write, '/a1/a10/'));
    }

    public function testOwnFacetRules(): void
    {
        $principal = $this->principal('vehicle.pricing:w:own');

        self::assertSame(['pricing'], $principal->deniedFacets('vehicle', ['pricing'], AccessLevel::Write, '/a1/a10/', ownerId: '7'));
        self::assertSame([], $principal->deniedFacets('vehicle', ['pricing'], AccessLevel::Write, '/a1/a10/', ownerId: '42'));
    }

    public function testReadOnlyImpersonationDeniesFacetWrites(): void
    {
        $principal = $this->principal('vehicle:w', ['act' => ['sub' => '7'], 'imp' => 'imp-1', 'imp_mode' => 'read_only']);

        self::assertSame(['pricing'], $principal->deniedFacets('vehicle', ['pricing'], AccessLevel::Write, '/a1/a10/'));
        self::assertSame([], $principal->deniedFacets('vehicle', ['pricing'], AccessLevel::Read, '/a1/a10/'));
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function principal(string $rights, array $claims = []): Principal
    {
        $claims += ['sub' => '42', 'dom' => '/a1/a10/', 'acl' => [['/a1/a10/', true, $rights]]];
        $token = new AccessToken('jti-1', '42', 'my-spa', [], new \DateTimeImmutable('+5 minutes'), null, $claims, 'raw');

        return new Principal('42', 'my-spa', [], $token, false);
    }
}
