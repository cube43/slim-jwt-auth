<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Lcobucci\JWT\Token\Plain;

class JwtDecodedToken
{
    public function __construct(public readonly Plain $payload, public readonly string $token)
    {
    }
}
