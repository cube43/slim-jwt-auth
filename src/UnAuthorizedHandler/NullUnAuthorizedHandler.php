<?php

declare(strict_types=1);

namespace Tuupola\Middleware\UnAuthorizedHandler;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

final readonly class NullUnAuthorizedHandler implements JwtAuthentificationUnAuthorizedHandler
{
    #[Override]
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
    {
        return $response;
    }
}
