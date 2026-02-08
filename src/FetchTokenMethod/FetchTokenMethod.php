<?php

declare(strict_types=1);

namespace Tuupola\Middleware\FetchTokenMethod;

use Psr\Http\Message\ServerRequestInterface;

interface FetchTokenMethod
{
    public function __invoke(ServerRequestInterface $request): null|string;
}
