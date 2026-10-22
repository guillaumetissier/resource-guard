<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Guard;

use GuillaumeTissier\ResourceGuard\Client\DpopProofFactory;
use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use GuillaumeTissier\ResourceGuard\Dpop\InMemoryReplayStore;
use GuillaumeTissier\ResourceGuard\Guard\AuthenticationFailed;
use GuillaumeTissier\ResourceGuard\Guard\Principal;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use GuillaumeTissier\ResourceGuard\Tests\Support\TokenFactory;
use GuillaumeTissier\ResourceGuard\Token\AccessTokenValidator;
use GuillaumeTissier\ResourceGuard\Token\Impersonation;
use GuillaumeTissier\ResourceGuard\Token\StaticJwksProvider;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ImpersonationTest extends TestCase
{
    private const URI = 'https://api.example.com/items';

    private TokenFactory $tokens;
    private DpopProofFactory $client;

    protected function setUp(): void
    {
        $this->tokens = new TokenFactory();
        $this->client = DpopProofFactory::withNewKey();
    }

    public function testRegularTokenIsNotImpersonated(): void
    {
        $principal = $this->call('POST', $this->token([]));

        self::assertFalse($principal->isImpersonated());
        self::assertNull($principal->actorId());
        self::assertFalse($principal->isReadOnly());
    }

    public function testReadOnlyImpersonationAllowsReads(): void
    {
        $principal = $this->call('GET', $this->token(['act' => ['sub' => '7'], 'imp' => 'imp-1', 'imp_mode' => Impersonation::MODE_READ_ONLY]));

        self::assertTrue($principal->isImpersonated());
        self::assertSame('42', $principal->userId);
        self::assertSame('7', $principal->actorId());
        self::assertSame('imp-1', $principal->token->impersonationId());
        self::assertTrue($principal->isReadOnly());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function writeMethods(): iterable
    {
        foreach (['POST', 'PUT', 'PATCH', 'DELETE'] as $method) {
            yield $method => [$method];
        }
    }

    #[DataProvider('writeMethods')]
    public function testReadOnlyImpersonationRefusesWrites(string $method): void
    {
        try {
            $this->call($method, $this->token(['act' => ['sub' => '7'], 'imp_mode' => Impersonation::MODE_READ_ONLY]));
            self::fail('A write must be refused during a read-only impersonation');
        } catch (AuthenticationFailed $e) {
            self::assertSame(403, $e->statusCode);
            self::assertSame('impersonation_read_only', $e->errorCode);
        }
    }

    public function testMissingOrUnknownModeFailsSafeAsReadOnly(): void
    {
        $this->expectException(AuthenticationFailed::class);
        $this->call('DELETE', $this->token(['act' => ['sub' => '7'], 'imp_mode' => 'something']));
    }

    public function testFullImpersonationAllowsWrites(): void
    {
        $principal = $this->call('DELETE', $this->token(['act' => ['sub' => '1'], 'imp_mode' => Impersonation::MODE_FULL]));

        self::assertTrue($principal->isImpersonated());
        self::assertFalse($principal->isReadOnly());
    }

    private function token(array $claims): string
    {
        return $this->tokens->issue(['cnf' => ['jkt' => $this->client->thumbprint()]] + $claims);
    }

    private function call(string $method, string $token): Principal
    {
        $guard = new ResourceGuard(
            new AccessTokenValidator(new StaticJwksProvider($this->tokens->keySet())),
            new DpopProofValidator(new InMemoryReplayStore()),
        );

        return $guard->authenticate($method, self::URI, 'DPoP '.$token, [$this->client->create($method, self::URI, $token)]);
    }
}
