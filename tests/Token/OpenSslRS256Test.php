<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Token;

use GuillaumeTissier\ResourceGuard\Token\OpenSslRS256;
use GuillaumeTissier\ResourceGuard\Util\RsaPem;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\TestCase;

final class OpenSslRS256Test extends TestCase
{
    public function testInteroperatesWithWebTokenRs256(): void
    {
        $key = JWKFactory::createRSAKey(2048, ['alg' => 'RS256']);
        $ours = new OpenSslRS256();
        $reference = new RS256();

        $signature = $ours->sign($key, 'payload');
        self::assertTrue($reference->verify($key->toPublic(), 'payload', $signature), 'web-token accepts our signature');
        self::assertTrue($ours->verify($key->toPublic(), 'payload', $reference->sign($key, 'payload')), 'we accept web-token\'s');
        self::assertFalse($ours->verify($key->toPublic(), 'tampered', $signature));
    }

    public function testPublicPemMatchesOpenSsl(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => \OPENSSL_KEYTYPE_RSA]);
        $details = openssl_pkey_get_details($resource);
        $jwk = JWKFactory::createFromKey($details['key']);

        self::assertSame($details['key'], RsaPem::publicKey($jwk));
    }

    public function testRejectsNonRsaKeys(): void
    {
        self::assertFalse((new OpenSslRS256())->verify(JWKFactory::createECKey('P-256')->toPublic(), 'payload', 'sig'));
    }
}
