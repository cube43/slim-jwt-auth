<?php

declare(strict_types=1);

namespace Unit;

use PHPUnit\Framework\TestCase;
use Tuupola\Middleware\JwtAuthentication\RuleInterface;
use Tuupola\Middleware\JwtAuthentication\Secret;
use Tuupola\Middleware\JwtAuthenticationOption;

class JwtAuthenticationOptionTest extends TestCase
{
    public function testDefaultValue(): void
    {
        $secret = self::createMock(Secret::class);
        $sUT    = JwtAuthenticationOption::create($secret);

        self::assertSame($secret, $sUT->secret);
        self::assertSame(true, $sUT->secure);
        self::assertSame(['localhost', '127.0.0.1'], $sUT->relaxed);
        self::assertSame('HS256', $sUT->algorithm);
        self::assertSame('Authorization', $sUT->header);
        self::assertSame('/Bearer\s+(.*)$/i', $sUT->regexp);
        self::assertSame('token', $sUT->cookie);
        self::assertSame('token', $sUT->attribute);
        self::assertSame(2, $sUT->rules->count());

        $newSecret = self::createMock(Secret::class);

        $sUT = $sUT->withSecret($newSecret);
        $sUT = $sUT->withSecure(false);
        $sUT = $sUT->withRelaxed(['toto6']);
        $sUT = $sUT->withAlgorithm('toto5');
        $sUT = $sUT->withHeader('toto4');
        $sUT = $sUT->withRegexp('toto2');
        $sUT = $sUT->withCookie('toto3');
        $sUT = $sUT->withAttribute('toto');

        self::assertSame($newSecret, $sUT->secret);
        self::assertSame(false, $sUT->secure);
        self::assertSame(['toto6'], $sUT->relaxed);
        self::assertSame('toto5', $sUT->algorithm);
        self::assertSame('toto4', $sUT->header);
        self::assertSame('toto2', $sUT->regexp);
        self::assertSame('toto3', $sUT->cookie);
        self::assertSame('toto', $sUT->attribute);
        self::assertSame(2, $sUT->rules->count());

        $rule = self::createMock(RuleInterface::class);

        $sUT = $sUT->addRule($rule);

        self::assertSame(3, $sUT->rules->count());

        $sUT = $sUT->withRules($rule);

        self::assertSame(1, $sUT->rules->count());
    }
}
