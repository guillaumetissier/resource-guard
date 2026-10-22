<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Access;

use GuillaumeTissier\ResourceGuard\Access\AccessExpression;
use GuillaumeTissier\ResourceGuard\Access\AccessLevel;
use GuillaumeTissier\ResourceGuard\Access\InvalidAccessExpression;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AccessExpressionTest extends TestCase
{
    public function testLevelsIncludeLowerOnes(): void
    {
        self::assertTrue(AccessLevel::Manage->includes(AccessLevel::Write));
        self::assertTrue(AccessLevel::Write->includes(AccessLevel::Read));
        self::assertFalse(AccessLevel::Read->includes(AccessLevel::Write));
        self::assertTrue(AccessLevel::None->includes(AccessLevel::None));
    }

    /**
     * @return iterable<string, array{string, string, bool, AccessLevel}>
     */
    public static function evaluations(): iterable
    {
        yield 'wildcard applies to any type' => ['*:w', 'vehicle', false, AccessLevel::Write];
        yield 'named type caps the wildcard' => ['*:w tire:r', 'tire', false, AccessLevel::Read];
        yield 'other types keep the wildcard' => ['*:w tire:r', 'vehicle', false, AccessLevel::Write];
        yield 'exclusion' => ['*:r tire:- invoice:-', 'invoice', false, AccessLevel::None];
        yield 'named type can exceed the wildcard' => ['*:r vehicle:m', 'vehicle', false, AccessLevel::Manage];
        yield 'nothing granted' => ['vehicle:w', 'tire', false, AccessLevel::None];
        yield 'own rule ignored for others' => ['user:w:own', 'user', false, AccessLevel::None];
        yield 'own rule for own resource' => ['user:w:own', 'user', true, AccessLevel::Write];
        yield 'read everybody, write own' => ['user:r user:w:own', 'user', true, AccessLevel::Write];
        yield 'general level kept for own' => ['user:m user:r:own', 'user', true, AccessLevel::Manage];
        yield 'wildcard own' => ['*:w:own', 'note', true, AccessLevel::Write];
        yield 'wildcard own still applies to a named type' => ['*:w:own tire:r', 'tire', true, AccessLevel::Write];
        yield 'read all, write own' => ['*:r user:w:own', 'user', false, AccessLevel::Read];
        yield 'wildcard never covers reserved types' => ['*:m', '@impersonate', false, AccessLevel::None];
        yield 'reserved type granted explicitly' => ['*:m @impersonate:r', '@impersonate', false, AccessLevel::Read];
        yield 'case insensitive' => ['Vehicle:W', 'VEHICLE', false, AccessLevel::Write];
        yield 'commas allowed' => ['*:r,tire:-', 'tire', false, AccessLevel::None];
    }

    #[DataProvider('evaluations')]
    public function testEvaluation(string $expression, string $type, bool $own, AccessLevel $expected): void
    {
        self::assertSame($expected, AccessExpression::parse($expression)->levelFor($type, $own));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidExpressions(): iterable
    {
        yield 'missing level' => ['vehicle'];
        yield 'unknown level' => ['vehicle:x'];
        yield 'unknown qualifier' => ['vehicle:w:all'];
        yield 'bad type' => ['ve hicle!:w'];
        yield 'duplicate' => ['vehicle:w vehicle:r'];
        yield 'too many parts' => ['vehicle:w:own:x'];
    }

    #[DataProvider('invalidExpressions')]
    public function testInvalidExpressionsAreRejected(string $expression): void
    {
        $this->expectException(InvalidAccessExpression::class);
        AccessExpression::parse($expression);
    }

    public function testCanonicalForm(): void
    {
        self::assertSame(
            '*:w invoice:- tire:r user:r user:w:own @access:w',
            AccessExpression::parse('@access:w user:w:own tire:r *:w user:r invoice:-')->toString(),
        );
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function delegations(): iterable
    {
        yield 'same rights' => ['*:w tire:r', '*:w tire:r', true];
        yield 'subset' => ['vehicle:r', '*:w', true];
        yield 'more on a named type' => ['tire:w', '*:w tire:r', false];
        yield 'wildcard beyond bound' => ['*:m', '*:w', false];
        yield 'wildcard within bound except capped type' => ['*:w', '*:w tire:r', false];
        yield 'wildcard with the same cap' => ['*:w tire:r', '*:m tire:r', true];
        yield 'reserved power not held' => ['@impersonate:r', '*:m', false];
        yield 'reserved power held' => ['@impersonate:r', '*:m @impersonate:w', true];
        yield 'own rights within general rights' => ['user:w:own', 'user:w', true];
        yield 'own rights beyond' => ['user:m:own', 'user:w', false];
        yield 'empty' => ['', 'vehicle:r', true];
    }

    #[DataProvider('delegations')]
    public function testDelegationBound(string $granted, string $bound, bool $expected): void
    {
        self::assertSame($expected, AccessExpression::parse($granted)->isWithin(AccessExpression::parse($bound)));
    }
}
