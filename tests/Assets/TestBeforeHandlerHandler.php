<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware\Assets;

use Lcobucci\JWT\Token\Plain;
use Override;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\BeforeHandler\JwtAuthentificationBeforeHandler;

final readonly class TestBeforeHandlerHandler implements JwtAuthentificationBeforeHandler
{
    #[Override]
    public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface
    {
        return $request->withAttribute('test', 'invoke');
    }
}
