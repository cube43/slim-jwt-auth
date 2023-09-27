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

use PHPUnit\Framework\TestCase;
use Tuupola\Http\Factory\ServerRequestFactory;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

class RequestPathRuleTest extends TestCase
{
    public function testWrongUri(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'api',
        );

        $rule = new RequestPathRule();
        self::assertTrue($rule($request));
    }

    public function testDefaultRule(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api',
        );

        $rule = new RequestPathRule();
        self::assertTrue($rule($request));
    }

    public function testIgnoreWithSlashesAtEnd(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api',
        );

        $rule = new RequestPathRule(['/'], ['/api/']);
        self::assertFalse($rule($request));
    }

    public function testShouldAcceptArrayAndStringAsPath(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api',
        );

        $rule = new RequestPathRule(['/api']);
        self::assertTrue($rule($request));

        $rule = new RequestPathRule(['/api', '/foo']);
        self::assertTrue($rule($request));
    }

    public function testShouldAuthenticateEverything(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/',
        );

        $rule = new RequestPathRule(['/']);
        self::assertTrue($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api',
        );

        self::assertTrue($rule($request));
    }

    public function testShouldAuthenticateOnlyApi(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/',
        );

        $rule = new RequestPathRule(['/api']);
        self::assertFalse($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api',
        );

        self::assertTrue($rule($request));
    }

    public function testShouldIgnoreLogin(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api',
        );

        $rule = new RequestPathRule(['/api'], ['/api/login']);
        self::assertTrue($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/login',
        );

        self::assertFalse($rule($request));
    }

    public function testShouldAuthenticateCreateAndList(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api',
        );

        /* Should not authenticate */
        $rule = new RequestPathRule(['/api/create', '/api/list']);
        self::assertFalse($rule($request));

        /* Should authenticate */
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api/create',
        );

        self::assertTrue($rule($request));

        /* Should authenticate */
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api/list',
        );

        self::assertTrue($rule($request));

        /* Should not authenticate */
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api/ping',
        );

        self::assertFalse($rule($request));
    }

    public function testShouldAuthenticateRegexp(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api/products/123/tickets/anything',
        );

        /* Should authenticate */
        $rule = new RequestPathRule(['/api/products/(\d*)/tickets']);
        self::assertTrue($rule($request));

        /* Should not authenticate */
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/api/products/xxx/tickets',
        );

        self::assertFalse($rule($request));
    }

    public function testBug50ShouldAuthenticateMultipleSlashes(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/',
        );

        $rule = new RequestPathRule(['/v1/api']);
        self::assertFalse($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/v1/api',
        );

        self::assertTrue($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/v1//api',
        );

        self::assertTrue($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com/v1//////api',
        );

        self::assertTrue($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com//v1/api',
        );

        self::assertTrue($rule($request));

        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'https://example.com//////v1/api',
        );

        self::assertTrue($rule($request));
    }
}
