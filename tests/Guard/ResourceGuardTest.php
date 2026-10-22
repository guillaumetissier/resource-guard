<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Guard;

use GuillaumeTissier\ResourceGuard\Client\DpopProofFactory;
use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use GuillaumeTissier\ResourceGuard\Dpop\InMemoryReplayStore;
use GuillaumeTissier\ResourceGuard\Guard\AuthenticationFailed;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use GuillaumeTissier\ResourceGuard\Tests\Support\TokenFactory;
use GuillaumeTissier\ResourceGuard\Token\AccessTokenValidator;
use GuillaumeTissier\ResourceGuard\Token\StaticJwksProvider;
use PHPUnit\Framework\TestCase;

final class ResourceGuardTest extends TestCase
{
    private const URI = 'https://api.example.com/items';

    private TokenFactory $tokens;
    private DpopProofFactory $client;

    protected function setUp(): void
    {
        $this->tokens = new TokenFactory();
        $this->client = DpopProofFactory::withNewKey();
    }

    public function testDpopBoundTokenWithValidProof(): void
    {
        $token = $this->boundToken(['scopes' => ['items.read']]);

        $principal = $this->guard()->authenticate('GET', self::URI, 'DPoP '.$token, [$this->client->create('GET', self::URI, $token)]);

        self::assertSame('42', $principal->userId);
        self::assertSame('spa-client', $principal->clientId);
        self::assertTrue($principal->hasScope('items.read'));
        self::assertTrue($principal->proofOfPossession);
    }

    public function testStolenBoundTokenIsUselessWithoutTheKey(): void
    {
        $token = $this->boundToken();
        $attacker = DpopProofFactory::withNewKey();

        $this->assertFailure('invalid_dpop_proof', fn () => $this->guard()
            ->authenticate('GET', self::URI, 'DPoP '.$token, [$attacker->create('GET', self::URI, $token)]));
    }

    public function testBoundTokenPresentedAsBearerIsRejected(): void
    {
        $this->assertFailure('invalid_token', fn () => $this->guard(requireDpop: false)
            ->authenticate('GET', self::URI, 'Bearer '.$this->boundToken()));
    }

    public function testBearerTokenAcceptedOnlyWhenDpopIsOptional(): void
    {
        $principal = $this->guard(requireDpop: false)->authenticate('GET', self::URI, 'Bearer '.$this->tokens->issue());
        self::assertFalse($principal->proofOfPossession);

        $this->assertFailure('invalid_token', fn () => $this->guard()
            ->authenticate('GET', self::URI, 'Bearer '.$this->tokens->issue()));
    }

    public function testMissingOrDuplicatedProofIsRejected(): void
    {
        $token = $this->boundToken();

        $this->assertFailure('invalid_dpop_proof', fn () => $this->guard()
            ->authenticate('GET', self::URI, 'DPoP '.$token));
        $this->assertFailure('invalid_dpop_proof', fn () => $this->guard()
            ->authenticate('GET', self::URI, 'DPoP '.$token, [
                $this->client->create('GET', self::URI, $token),
                $this->client->create('GET', self::URI, $token),
            ]));
    }

    public function testExpiredTokenIsRejected(): void
    {
        $token = $this->boundToken(['exp' => time() - 3600]);

        $this->assertFailure('invalid_token', fn () => $this->guard()
            ->authenticate('GET', self::URI, 'DPoP '.$token, [$this->client->create('GET', self::URI, $token)]));
    }

    public function testTokenSignedByAnotherKeyIsRejected(): void
    {
        $token = $this->tokens->issue(['cnf' => ['jkt' => $this->client->thumbprint()]], (new TokenFactory())->key);

        $this->assertFailure('invalid_token', fn () => $this->guard()
            ->authenticate('GET', self::URI, 'DPoP '.$token, [$this->client->create('GET', self::URI, $token)]));
    }

    public function testClientAllowList(): void
    {
        $token = $this->boundToken(['aud' => 'other-client']);

        $this->assertFailure('invalid_token', fn () => $this->guard(allowedClients: ['spa-client'])
            ->authenticate('GET', self::URI, 'DPoP '.$token, [$this->client->create('GET', self::URI, $token)]));
    }

    public function testNoCredentialsGivesBareChallenge(): void
    {
        $e = $this->assertFailure('', fn () => $this->guard()->authenticate('GET', self::URI, null));

        self::assertSame('DPoP algs="ES256 ES384 RS256 PS256 EdDSA"', $e->wwwAuthenticate());
    }

    /**
     * @param list<string> $allowedClients
     */
    private function guard(bool $requireDpop = true, array $allowedClients = []): ResourceGuard
    {
        return new ResourceGuard(
            new AccessTokenValidator(new StaticJwksProvider($this->tokens->keySet()), $allowedClients),
            new DpopProofValidator(new InMemoryReplayStore()),
            $requireDpop,
        );
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function boundToken(array $overrides = []): string
    {
        return $this->tokens->issue(['cnf' => ['jkt' => $this->client->thumbprint()]] + $overrides);
    }

    private function assertFailure(string $expectedErrorCode, callable $attempt): AuthenticationFailed
    {
        try {
            $attempt();
        } catch (AuthenticationFailed $e) {
            self::assertSame($expectedErrorCode, $e->errorCode, $e->getMessage());

            return $e;
        }

        self::fail('Expected an AuthenticationFailed exception');
    }
}
