<?php

declare(strict_types=1);

namespace Unit;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use PHPUnit\Framework\TestCase;
use Tuupola\Middleware\JwtAuthenticationOption;

/** @psalm-suppress UnusedClass */
class JwtAuthenticationOptionTest extends TestCase
{
    public function testDefaultValue(): void
    {
        $secret = self::createMock(Key::class);
        $sUT    = JwtAuthenticationOption::create($secret);

        self::assertSame($secret, $sUT->secret);
        self::assertSame(true, $sUT->secure);
        self::assertSame(['localhost', '127.0.0.1'], $sUT->relaxed);
        self::assertInstanceOf(Signer\Hmac\Sha256::class, $sUT->algorithm);
        self::assertSame('Authorization', $sUT->header);
        self::assertSame('/Bearer\s+(.*)$/i', $sUT->regexp);
        self::assertSame('token', $sUT->cookie);
        self::assertSame('token', $sUT->attribute);

        $newSecret = self::createMock(Key::class);
        $algo      = self::createMock(Signer::class);

        $sUT = $sUT->withSecret($newSecret);
        $sUT = $sUT->withSecure(false);
        $sUT = $sUT->withRelaxed(['toto6']);
        $sUT = $sUT->withAlgorithm($algo);
        $sUT = $sUT->withHeader('toto4');
        $sUT = $sUT->withRegexp('toto2');
        $sUT = $sUT->withCookie('toto3');
        $sUT = $sUT->withAttribute('toto');

        self::assertSame($newSecret, $sUT->secret);
        self::assertSame(false, $sUT->secure);
        self::assertSame(['toto6'], $sUT->relaxed);
        self::assertSame($algo, $sUT->algorithm);
        self::assertSame('toto4', $sUT->header);
        self::assertSame('toto2', $sUT->regexp);
        self::assertSame('toto3', $sUT->cookie);
        self::assertSame('toto', $sUT->attribute);
    }
}
