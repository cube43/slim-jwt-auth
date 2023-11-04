<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthentificationBeforeHandler;

class NullBeforeHandler implements JwtAuthentificationBeforeHandler
{
    public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface
    {
        return $request;
    }
}
