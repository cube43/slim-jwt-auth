<?php

declare(strict_types=1);

namespace Tuupola\Middleware\Rule;

use Override;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

use function in_array;

/**
 * Rule to decide by HTTP verb whether the request should be authenticated or not.
 */
final readonly class IgnoreHttpMethodRule implements RuleInterface
{
    /** @param string[] $ignoreHttpMethod */
    public function __construct(#[SensitiveParameter]
    private array $ignoreHttpMethod = ['OPTIONS'])
    {
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): bool
    {
        return ! in_array($request->getMethod(), $this->ignoreHttpMethod);
    }
}
