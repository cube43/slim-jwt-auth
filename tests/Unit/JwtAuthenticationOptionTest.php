<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware\Unit;

use Lcobucci\JWT\Signer\Key;
use PHPUnit\Framework\TestCase;
use Tuupola\Middleware\AfterHandler\JwtAuthentificationAfterHandler;
use Tuupola\Middleware\BeforeHandler\JwtAuthentificationBeforeHandler;
use Tuupola\Middleware\JwtAuthenticationOption;
use Tuupola\Middleware\Security\AllowedInsecureHosts;
use Tuupola\Middleware\Security\JwtAuthentificationSecurity;

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
        $security  = self::createMock(JwtAuthentificationSecurity::class);

        $sUT = $sUT->withSecret($newSecret);
        $sUT = $sUT->withTokenAttributeName('toto');
        $sUT = $sUT->withSecurity($security);
        $sUT = $sUT->withBeforeHandleRequestWhenTokenAvailable($before);
        $sUT = $sUT->withAfterHandleRequestWhenTokenAvailable($after);

        self::assertSame($newSecret, $sUT->secret);
        self::assertSame($security, $sUT->security);
        self::assertSame('toto', $sUT->tokenAttributeName);
        self::assertSame($before, $sUT->beforeHandleRequestWhenTokenAvailable);
        self::assertSame($after, $sUT->afterHandleRequestWhenTokenAvailable);
    }
}
