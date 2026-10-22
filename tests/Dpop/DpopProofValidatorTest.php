<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Dpop;

use GuillaumeTissier\ResourceGuard\Client\DpopProofFactory;
use GuillaumeTissier\ResourceGuard\Dpop\DpopException;
use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use GuillaumeTissier\ResourceGuard\Dpop\InMemoryReplayStore;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DpopProofValidatorTest extends TestCase
{
    private const URI = 'https://api.example.com/orders';

    private DpopProofFactory $client;
    private DpopProofValidator $validator;

    protected function setUp(): void
    {
        $this->client = DpopProofFactory::withNewKey();
        $this->validator = new DpopProofValidator(new InMemoryReplayStore());
    }

    public function testValidProofReturnsTheKeyThumbprint(): void
    {
        $proof = $this->validator->validate($this->client->create('POST', self::URI), 'POST', self::URI);

        self::assertSame($this->client->thumbprint(), $proof->jkt);
    }

    public function testHtuComparisonIgnoresQueryAndDefaultPort(): void
    {
        $proof = $this->client->create('GET', 'https://API.example.com:443/orders');

        $this->validator->validate($proof, 'GET', 'https://api.example.com/orders?page=2');
        $this->addToAssertionCount(1);
    }

    public function testReplayedProofIsRejected(): void
    {
        $proof = $this->client->create('POST', self::URI);
        $this->validator->validate($proof, 'POST', self::URI);

        $this->expectExceptionObject(DpopException::because('proof has already been used'));
        $this->validator->validate($proof, 'POST', self::URI);
    }

    public function testAccessTokenHashIsChecked(): void
    {
        $proof = $this->client->create('GET', self::URI, 'token-A');

        $this->validator->validate($proof, 'GET', self::URI, 'token-A');

        $this->expectException(DpopException::class);
        $this->validator->validate($this->client->create('GET', self::URI, 'token-A'), 'GET', self::URI, 'token-B');
    }

    public function testProofFromAnotherKeyIsRejectedForBoundToken(): void
    {
        $other = DpopProofFactory::withNewKey();

        $this->expectExceptionMessage('proof key does not match');
        $this->validator->validate($other->create('GET', self::URI), 'GET', self::URI, null, $this->client->thumbprint());
    }

    /**
     * @return iterable<string, array{string, string, int}>
     */
    public static function mismatches(): iterable
    {
        yield 'wrong method' => ['GET', self::URI, 0];
        yield 'wrong uri' => ['POST', 'https://api.example.com/other', 0];
        yield 'too old' => ['POST', self::URI, -600];
        yield 'from the future' => ['POST', self::URI, 120];
    }

    #[DataProvider('mismatches')]
    public function testMismatchesAreRejected(string $method, string $uri, int $iatShift): void
    {
        $proof = $this->client->create('POST', self::URI, null, null, time() + $iatShift);

        $this->expectException(DpopException::class);
        $this->validator->validate($proof, $method, $uri);
    }

    public function testTamperedSignatureIsRejected(): void
    {
        $proof = $this->client->create('POST', self::URI);
        [$h, $p, $s] = explode('.', $proof);
        $payload = json_decode(base64_decode(strtr($p, '-_', '+/')), true);
        self::assertIsArray($payload);
        $payload['htu'] = 'https://evil.example.com/orders';
        $forged = $h.'.'.rtrim(strtr(base64_encode((string) json_encode($payload, \JSON_UNESCAPED_SLASHES)), '+/', '-_'), '=').'.'.$s;

        $this->expectExceptionMessage('invalid proof signature');
        $this->validator->validate($forged, 'POST', 'https://evil.example.com/orders');
    }

    public function testSymmetricKeysAreRejected(): void
    {
        $key = JWKFactory::createOctKey(256);
        $jws = (new JWSBuilder(new AlgorithmManager([new HS256()])))
            ->create()
            ->withPayload((string) json_encode(['jti' => 'x', 'htm' => 'POST', 'htu' => self::URI, 'iat' => time()]))
            ->addSignature($key, ['alg' => 'HS256', 'typ' => 'dpop+jwt', 'jwk' => $key->all()])
            ->build();

        $this->expectException(DpopException::class);
        $this->validator->validate((new CompactSerializer())->serialize($jws, 0), 'POST', self::URI);
    }

    public function testPrivateKeyInHeaderIsRejected(): void
    {
        $key = $this->client->privateKey();
        $jws = (new JWSBuilder(new AlgorithmManager([new \Jose\Component\Signature\Algorithm\ES256()])))
            ->create()
            ->withPayload((string) json_encode(['jti' => 'x', 'htm' => 'POST', 'htu' => self::URI, 'iat' => time()]))
            ->addSignature($key, ['alg' => 'ES256', 'typ' => 'dpop+jwt', 'jwk' => $key->all()])
            ->build();

        $this->expectExceptionMessage('private key material');
        $this->validator->validate((new CompactSerializer())->serialize($jws, 0), 'POST', self::URI);
    }

    public function testGarbageIsRejected(): void
    {
        $this->expectException(DpopException::class);
        $this->validator->validate('not-a-jwt', 'POST', self::URI);
    }
}
