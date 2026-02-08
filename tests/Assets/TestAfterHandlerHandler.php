<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware\Assets;

use Lcobucci\JWT\Token\Plain;
use Override;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Middleware\JwtAuthentificationAfterHandler;

final readonly class TestAfterHandlerHandler implements JwtAuthentificationAfterHandler
{
    #[Override]
    public function __invoke(ResponseInterface $response, Plain $token): ResponseInterface
    {
        $response->getBody()->write(self::class);

        return $response->withHeader('X-Brawndo', 'plants crave');
    }
}
