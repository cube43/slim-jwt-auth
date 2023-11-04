<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Psr\Http\Message\ServerRequestInterface;

use function in_array;

/**
 * Rule to decide by HTTP verb whether the request should be authenticated or not.
 */
final class IgnoreHttpMethodRule implements RuleInterface
{
    /** @param string[] $ignoreHttpMethod */
    public function __construct(private readonly array $ignoreHttpMethod = ['OPTIONS'])
    {
    }

    public function __invoke(ServerRequestInterface $request): bool
    {
        return ! in_array($request->getMethod(), $this->ignoreHttpMethod);
    }
}
