<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware\Assets;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthentificationBeforeHandler;

class TestBeforeHandlerHandler implements JwtAuthentificationBeforeHandler
{
    public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface
    {
        return $request->withAttribute('test', 'invoke');
    }
}
