<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthentificationBefore;

class NullBefore implements JwtAuthentificationBefore
{
    public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface
    {
        return $request;
    }
}
