<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Tests\Webhook;

use GuillaumeTissier\ResourceGuard\Webhook\WebhookEvent;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookSignature;
use PHPUnit\Framework\TestCase;

final class WebhookSignatureTest extends TestCase
{
    private const SECRET = 'a-very-long-shared-secret-of-at-least-32-chars';

    public function testRoundTrip(): void
    {
        $signature = new WebhookSignature(self::SECRET);
        $payload = (new WebhookEvent('evt_1', WebhookEvent::USER_CREATED, new \DateTimeImmutable(), ['user_id' => '42']))->toJson();

        self::assertTrue($signature->verify($payload, $signature->sign($payload)));
        self::assertSame('42', WebhookEvent::fromJson($payload)->userId());
    }

    public function testTamperedPayloadOrWrongSecretFails(): void
    {
        $signature = new WebhookSignature(self::SECRET);
        $header = $signature->sign('{"a":1}');

        self::assertFalse($signature->verify('{"a":2}', $header));
        self::assertFalse((new WebhookSignature(str_repeat('x', 40)))->verify('{"a":1}', $header));
        self::assertFalse($signature->verify('{"a":1}', null));
    }

    public function testOldDeliveryIsRejected(): void
    {
        $signature = new WebhookSignature(self::SECRET, 300);
        $header = $signature->sign('{}', time() - 3600);

        self::assertFalse($signature->verify('{}', $header));
    }
}
