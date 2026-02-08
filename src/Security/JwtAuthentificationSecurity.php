<?php

declare(strict_types=1);

namespace Tuupola\Middleware\Security;

use Psr\Http\Message\ServerRequestInterface;

interface JwtAuthentificationSecurity
{
    public function __invoke(ServerRequestInterface $request): bool;
}
