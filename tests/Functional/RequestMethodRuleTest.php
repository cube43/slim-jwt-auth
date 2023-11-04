<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Tuupola\Middleware\JwtAuthentication\IgnoreHttpMethodRule;

/** @psalm-suppress UnusedClass */
class RequestMethodRuleTest extends TestCase
{
    public function testShouldNotAuthenticateOptions(): void
    {
        $request = new ServerRequest(
            [],
            [],
            'https://example.com/api',
            'OPTIONS',
        );

        $rule = new IgnoreHttpMethodRule();

        self::assertFalse($rule($request));
    }

    public function testShouldAuthenticatePost(): void
    {
        $request = new ServerRequest(
            [],
            [],
            'https://example.com/api',
            'POST',
        );

        $rule = new IgnoreHttpMethodRule();

        self::assertTrue($rule($request));
    }

    public function testShouldAuthenticateGet(): void
    {
        $request = new ServerRequest(
            [],
            [],
            'https://example.com/api',
            'GET',
        );

        $rule = new IgnoreHttpMethodRule();

        self::assertTrue($rule($request));
    }

    public function testShouldConfigureIgnore(): void
    {
        $request = new ServerRequest(
            [],
            [],
            'https://example.com/api',
            'GET',
        );

        $rule = new IgnoreHttpMethodRule(['GET']);

        self::assertFalse($rule($request));
    }
}
