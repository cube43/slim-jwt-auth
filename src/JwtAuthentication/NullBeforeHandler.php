<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Lcobucci\JWT\Token\Plain;
use Override;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthentificationBeforeHandler;

final readonly class NullBeforeHandler implements JwtAuthentificationBeforeHandler
{
    #[Override]
    public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface
    {
        return $request;
    }
}
