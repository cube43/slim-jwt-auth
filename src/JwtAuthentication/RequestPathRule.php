<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Psr\Http\Message\ServerRequestInterface;

use function array_filter;
use function array_map;
use function explode;
use function implode;
use function preg_match;
use function rtrim;

/**
 * Rule to decide by request path whether the request should be authenticated or not.
 */
final class RequestPathRule implements RuleInterface
{
    /** @var string[] */
    private readonly array $mustBeAuthOnUri;
    /** @var string[] */
    private readonly array $ignoreAuthOnUri;

    /**
     * @param string[] $mustBeAuthOnUri
     * @param string[] $ignoreAuthOnUri
     */
    public function __construct(
        array $mustBeAuthOnUri = ['/'],
        array $ignoreAuthOnUri = []
    ) {
        $this->mustBeAuthOnUri = array_map(static fn (string $mustBeAuthOnUri): string => rtrim($mustBeAuthOnUri, '/'), $mustBeAuthOnUri);
        $this->ignoreAuthOnUri = array_map(static fn (string $ignoreAuthOnUri): string => rtrim($ignoreAuthOnUri, '/'), $ignoreAuthOnUri);
    }

    public function __invoke(ServerRequestInterface $request): bool
    {
        $uri = '/' . implode(
            '/',
            array_filter(explode('//', '/' . $request->getUri()->getPath())),
        );

        if ($this->shouldIgnoreAuthOnUri($uri)) {
            return false;
        }

        return $this->shouldBeAuthenticate($uri);
    }

    /**
     * If request path is matches ignore should not authenticate.
     */
    private function shouldIgnoreAuthOnUri(string $uri): bool
    {
        foreach ($this->ignoreAuthOnUri as $ignoreAuthOnUri) {
            if ($this->match($ignoreAuthOnUri, $uri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Otherwise check if path matches and we should authenticate.
     */
    private function shouldBeAuthenticate(string $uri): bool
    {
        foreach ($this->mustBeAuthOnUri as $mustBeAuthOnUri) {
            if ($this->match($mustBeAuthOnUri, $uri)) {
                return true;
            }
        }

        return false;
    }

    private function match(string $value, string $uri): bool
    {
        return ! ! preg_match('@^' . $value . '(/.*)?$@', $uri);
    }
}
