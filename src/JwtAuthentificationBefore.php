<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ServerRequestInterface;

interface JwtAuthentificationBefore
{
    public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface;
}
