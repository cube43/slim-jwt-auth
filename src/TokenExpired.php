<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use RuntimeException;

class TokenExpired extends RuntimeException
{
    public static function create(): self
    {
        return new self('Token expired');
    }
}
