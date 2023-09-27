<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use RuntimeException;

class NotAuthorized extends RuntimeException
{
    public static function create(): self
    {
        return new self('Not authorized.');
    }
}
