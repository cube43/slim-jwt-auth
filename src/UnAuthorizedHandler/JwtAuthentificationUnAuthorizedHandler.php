<?php

declare(strict_types=1);

namespace Tuupola\Middleware\UnAuthorizedHandler;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

interface JwtAuthentificationUnAuthorizedHandler
{
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface;
}
