<?php

declare(strict_types=1);

namespace Functional;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tuupola\Middleware\JwtDecodedToken;

class JwtDecodedTokenTest extends TestCase
{
    public function testOk(): void
    {
        $sUT = new JwtDecodedToken(['my' => 'payload', 'array' => ['foo', 'bar']], 'token');

        self::assertSame(['my' => 'payload', 'array' => ['foo', 'bar']], $sUT->payload);
        self::assertSame('token', $sUT->token);
        self::assertSame('payload', $sUT->getStringAttribute('my'));
        self::assertSame(['foo', 'bar'], $sUT->getArrayAttribute('array'));
    }

    public function testFailCauseStringDoesNotExist(): void
    {
        $sUT = new JwtDecodedToken(['my' => 'payload', 'array' => ['foo', 'bar']], 'token');

        self::expectException(RuntimeException::class);
        self::expectExceptionMessage('Attribute `hello` does not exist');
        $sUT->getStringAttribute('hello');
    }

    public function testFailCauseStringDoesNotAString(): void
    {
        $sUT = new JwtDecodedToken(['my' => 'payload', 'array' => ['foo', 'bar']], 'token');

        self::expectException(RuntimeException::class);
        self::expectExceptionMessage('Attribute `array` is not a string');
        $sUT->getStringAttribute('array');
    }

    public function testFailCauseArrayDoesNotExist(): void
    {
        $sUT = new JwtDecodedToken(['my' => 'payload', 'array' => ['foo', 'bar']], 'token');

        self::expectException(RuntimeException::class);
        self::expectExceptionMessage('Attribute `hello` does not exist');
        $sUT->getArrayAttribute('hello');
    }

    public function testFailCauseArrayDoesNotAString(): void
    {
        $sUT = new JwtDecodedToken(['my' => 'payload', 'array' => ['foo', 'bar']], 'token');

        self::expectException(RuntimeException::class);
        self::expectExceptionMessage('Attribute `my` is not an array');
        $sUT->getArrayAttribute('my');
    }
}
