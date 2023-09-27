<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Middleware\JwtAuthentificationAfter;

class NullAfter implements JwtAuthentificationAfter
{
    public function __invoke(ResponseInterface $response, Plain $token): ResponseInterface
    {
        return $response;
    }
}
