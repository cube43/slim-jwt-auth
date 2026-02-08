<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Lcobucci\JWT\Token\Plain;
use Override;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Middleware\JwtAuthentificationAfterHandler;

final readonly class NullAfterHandler implements JwtAuthentificationAfterHandler
{
    #[Override]
    public function __invoke(ResponseInterface $response, Plain $token): ResponseInterface
    {
        return $response;
    }
}
