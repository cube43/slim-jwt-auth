<?php

declare(strict_types=1);

namespace Tuupola\Middleware\AfterHandler;

use Lcobucci\JWT\Token\Plain;
use Override;
use Psr\Http\Message\ResponseInterface;
use SensitiveParameter;

final readonly class NullAfterHandler implements JwtAuthentificationAfterHandler
{
    #[Override]
    public function __invoke(ResponseInterface $response, #[SensitiveParameter]
    Plain $token): ResponseInterface
    {
        return $response;
    }
}
