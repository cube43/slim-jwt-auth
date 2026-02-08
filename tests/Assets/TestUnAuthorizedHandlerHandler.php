<?php

declare(strict_types=1);

namespace Tuupola\Tests\Middleware\Assets;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Tuupola\Middleware\UnAuthorizedHandler\JwtAuthentificationUnAuthorizedHandler;

final readonly class TestUnAuthorizedHandlerHandler implements JwtAuthentificationUnAuthorizedHandler
{
    #[Override]
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
    {
        $response->getBody()->write(self::class);

        return $response
            ->withStatus(402)
            ->withHeader('X-Foo', 'Bar');
    }
}
