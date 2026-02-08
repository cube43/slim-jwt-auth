<?php

declare(strict_types=1);

namespace Tuupola\Middleware\BeforeHandler;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

interface JwtAuthentificationBeforeHandler
{
    public function __invoke(ServerRequestInterface $request, #[SensitiveParameter]
    Plain $token): ServerRequestInterface;
}
