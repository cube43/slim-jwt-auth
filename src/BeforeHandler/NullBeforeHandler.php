<?php

declare(strict_types=1);

namespace Tuupola\Middleware\BeforeHandler;

use Lcobucci\JWT\Token\Plain;
use Override;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

final readonly class NullBeforeHandler implements JwtAuthentificationBeforeHandler
{
    #[Override]
    public function __invoke(ServerRequestInterface $request, #[SensitiveParameter]
    Plain $token): ServerRequestInterface
    {
        return $request;
    }
}
