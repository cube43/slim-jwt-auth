<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ResponseInterface;

interface JwtAuthentificationAfter
{
    public function __invoke(ResponseInterface $response, Plain $token): ResponseInterface;
}
