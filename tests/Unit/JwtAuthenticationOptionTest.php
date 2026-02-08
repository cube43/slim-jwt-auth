<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware\Unit;

use Lcobucci\JWT\Signer\Key;
use PHPUnit\Framework\TestCase;
use Tuupola\Middleware\AllowedInsecureHosts;
use Tuupola\Middleware\JwtAuthenticationOption;
use Tuupola\Middleware\JwtAuthentificationAfterHandler;
use Tuupola\Middleware\JwtAuthentificationBeforeHandler;
use Tuupola\Middleware\NullSecurity;

/** @psalm-suppress UnusedClass */
final class JwtAuthenticationOptionTest extends TestCase
{
    public function testDefaultValue(): void
    {
        $secret = self::createMock(Key::class);
        $sUT    = JwtAuthenticationOption::create($secret);

        self::assertSame($secret, $sUT->secret);
        self::assertInstanceOf(AllowedInsecureHosts::class, $sUT->security);
        self::assertSame('token', $sUT->tokenAttributeName);

        $newSecret = self::createMock(Key::class);
        $before    = self::createMock(JwtAuthentificationBeforeHandler::class);
        $after     = self::createMock(JwtAuthentificationAfterHandler::class);

        $sUT = $sUT->withSecret($newSecret);
        $sUT = $sUT->withTokenAttributeName('toto');
        $sUT = $sUT->withSecurity(new NullSecurity());
        $sUT = $sUT->withBeforeHandleRequestWhenTokenAvailable($before);
        $sUT = $sUT->withAfterHandleRequestWhenTokenAvailable($after);

        self::assertSame($newSecret, $sUT->secret);
        self::assertInstanceOf(NullSecurity::class, $sUT->security);
        self::assertSame('toto', $sUT->tokenAttributeName);
        self::assertSame($before, $sUT->beforeHandleRequestWhenTokenAvailable);
        self::assertSame($after, $sUT->afterHandleRequestWhenTokenAvailable);
    }
}
