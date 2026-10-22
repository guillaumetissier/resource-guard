<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Token;

use GuillaumeTissier\ResourceGuard\Tests\Support\ArrayCache;
use GuillaumeTissier\ResourceGuard\Tests\Support\TokenFactory;
use GuillaumeTissier\ResourceGuard\Token\HttpJwksProvider;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class HttpJwksProviderTest extends TestCase
{
    private ClientInterface $client;
    private int $fetches = 0;

    protected function setUp(): void
    {
        $jwks = json_encode((new TokenFactory())->keySet());
        $this->client = new class($jwks, $this->fetches) implements ClientInterface {
            public function __construct(private string $jwks, private int &$fetches)
            {
            }

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                ++$this->fetches;

                return new Response(200, ['Content-Type' => 'application/json'], $this->jwks);
            }
        };
    }

    public function testKeySetIsCachedAcrossInstances(): void
    {
        $cache = new ArrayCache();
        $this->provider($cache)->getKeySet();
        $this->provider($cache)->getKeySet();

        self::assertSame(1, $this->fetches);
    }

    public function testForcedRefreshesAreRateLimitedAcrossInstances(): void
    {
        // Each request of a PHP-FPM worker builds its own provider: the limit must survive that.
        $cache = new ArrayCache();
        $this->provider($cache)->getKeySet();
        $this->provider($cache)->getKeySet(forceRefresh: true);
        $this->provider($cache)->getKeySet(forceRefresh: true);
        $this->provider($cache)->getKeySet(forceRefresh: true);

        self::assertSame(2, $this->fetches, 'one initial fetch, then a single forced refresh per minute');
    }

    private function provider(ArrayCache $cache): HttpJwksProvider
    {
        return new HttpJwksProvider('https://auth.test/.well-known/jwks.json', $this->client, new Psr17Factory(), $cache);
    }
}
