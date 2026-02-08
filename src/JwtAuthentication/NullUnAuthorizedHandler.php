<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Tuupola\Middleware\JwtAuthentificationUnAuthorizedHandler;

final readonly class NullUnAuthorizedHandler implements JwtAuthentificationUnAuthorizedHandler
{
    #[Override]
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
    {
        return $response;
    }
}
