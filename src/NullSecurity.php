<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Override;
use Psr\Http\Message\ServerRequestInterface;

final readonly class NullSecurity implements JwtAuthentificationSecurity
{
    #[Override]
    public function __invoke(ServerRequestInterface $request): bool
    {
        return true;
    }
}
