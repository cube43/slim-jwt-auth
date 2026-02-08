<?php

declare(strict_types=1);

namespace Tuupola\Middleware\Rule;

use Override;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

use function array_any;
use function array_filter;
use function array_map;
use function explode;
use function implode;
use function preg_match;
use function rtrim;

/**
 * Rule to decide by request path whether the request should be authenticated or not.
 */
final readonly class RequestPathRule implements RuleInterface
{
    /** @var string[] */
    private array $mustBeAuthOnUri;
    /** @var string[] */
    private array $ignoreAuthOnUri;

    /**
     * @param string[] $mustBeAuthOnUri
     * @param string[] $ignoreAuthOnUri
     */
    public function __construct(
        #[SensitiveParameter]
        array $mustBeAuthOnUri = ['/'],
        #[SensitiveParameter]
        array $ignoreAuthOnUri = []
    ) {
        $this->mustBeAuthOnUri = array_map(static fn (string $mustBeAuthOnUri): string => rtrim($mustBeAuthOnUri, '/'), $mustBeAuthOnUri);
        $this->ignoreAuthOnUri = array_map(static fn (string $ignoreAuthOnUri): string => rtrim($ignoreAuthOnUri, '/'), $ignoreAuthOnUri);
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): bool
    {
        $uri = $this->cleanUri($request);

        if (array_any($this->ignoreAuthOnUri, fn ($ignoreAuthOnUri) => $this->match($ignoreAuthOnUri, $uri))) {
            return false;
        }

        return array_any($this->mustBeAuthOnUri, fn ($mustBeAuthOnUri) => $this->match($mustBeAuthOnUri, $uri));
    }

    private function match(string $value, string $uri): bool
    {
        return ! ! preg_match('@^' . $value . '(/.*)?$@', $uri);
    }

    private function cleanUri(ServerRequestInterface $request): string
    {
        $exploded = explode('//', '/' . $request->getUri()->getPath());
        $exploded = array_filter($exploded);
        $imploded = implode('/', $exploded);

        return '/' . $imploded;
    }
}
