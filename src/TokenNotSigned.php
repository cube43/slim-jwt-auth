<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use RuntimeException;

final class TokenNotSigned extends RuntimeException
{
    public static function create(): self
    {
        return new self('Token not signed');
    }
}
