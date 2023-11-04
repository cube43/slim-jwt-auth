<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware\Assets;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Middleware\JwtAuthentificationAfterHandler;

class TestAfterHandlerHandler implements JwtAuthentificationAfterHandler
{
    public function __invoke(ResponseInterface $response, Plain $token): ResponseInterface
    {
        $response->getBody()->write(self::class);

        return $response->withHeader('X-Brawndo', 'plants crave');
    }
}
