<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Middleware\JwtAuthentificationAfterHandler;

class NullAfterHandler implements JwtAuthentificationAfterHandler
{
    public function __invoke(ResponseInterface $response, Plain $token): ResponseInterface
    {
        return $response;
    }
}
