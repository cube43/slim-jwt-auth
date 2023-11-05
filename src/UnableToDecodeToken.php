<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use RuntimeException;
use Throwable;

class UnableToDecodeToken extends RuntimeException
{
    public static function create(Throwable $previous): self
    {
        return new self('Unable to decode token.', previous:  $previous);
    }
}
