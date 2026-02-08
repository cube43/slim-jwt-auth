<?php

declare(strict_types=1);

namespace Tuupola\Middleware\AfterHandler;

use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ResponseInterface;
use SensitiveParameter;

interface JwtAuthentificationAfterHandler
{
    public function __invoke(ResponseInterface $response, #[SensitiveParameter]
    Plain $token): ResponseInterface;
}
