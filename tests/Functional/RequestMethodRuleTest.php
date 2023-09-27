<?php

declare(strict_types=1);

/*

Copyright (c) 2015-2022 Mika Tuupola

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

/**
 * @see       https://github.com/tuupola/slim-jwt-auth
 * @see       https://appelsiini.net/projects/slim-jwt-auth
 */

namespace Tuupola\Tests\Middleware;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;

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

        $rule = new RequestMethodRule();

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

        $rule = new RequestMethodRule();

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

        $rule = new RequestMethodRule();

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

        $rule = new RequestMethodRule(['GET']);

        self::assertFalse($rule($request));
    }
}
