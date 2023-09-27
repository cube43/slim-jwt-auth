<?php

declare(strict_types=1);

namespace Functional;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Http\Factory\ServerRequestFactory;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;
use Tuupola\Middleware\JwtAuthentication\StringSecret;
use Tuupola\Middleware\JwtAuthenticationOption;
use Tuupola\Middleware\JwtAuthentificationAcl;

class JwtAuthentificationAclTest extends TestCase
{
    public function testShouldHandlePsr7(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api');

        $response = (new ResponseFactory())->createResponse();

        $option =                 JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withRules(new RequestPathRule(['/'], ['/api']));

        $auth = new JwtAuthentificationAcl($option);

        $next = static function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write('Success');

            return $response;
        };

        $response = $auth($request, $response, $next);

        self::assertEquals(200, $response->getStatusCode());
        self::assertEquals('Success', $response->getBody());
    }
}
