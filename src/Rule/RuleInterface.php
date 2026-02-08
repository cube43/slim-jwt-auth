<?php

declare(strict_types=1);

namespace Tuupola\Middleware\Rule;

use Psr\Http\Message\ServerRequestInterface;

interface RuleInterface
{
    public function __invoke(ServerRequestInterface $request): bool;
}
