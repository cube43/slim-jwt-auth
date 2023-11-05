<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use RuntimeException;

class TokenNotSigned extends RuntimeException
{
    public static function create(): self
    {
        return new self('Token not signed');
    }
}
