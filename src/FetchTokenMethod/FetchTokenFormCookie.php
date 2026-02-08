<?php

declare(strict_types=1);

namespace Tuupola\Middleware\FetchTokenMethod;

use Override;
use Psr\Http\Message\ServerRequestInterface;

use function array_key_exists;
use function is_string;
use function preg_match;

final readonly class FetchTokenFormCookie implements FetchTokenMethod
{
    /**
     * @param non-empty-string $cookie
     * @param non-empty-string $regexp
     */
    public function __construct(
        private string $cookie = 'token',
        private string $regexp = '/Bearer\s+(.*)$/i',
    ) {
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): null|string
    {
        $cookieParams = $request->getCookieParams();

        if (! array_key_exists($this->cookie, $cookieParams) || ! is_string($cookieParams[$this->cookie])) {
            return null;
        }

        $matches = [];

        if (preg_match($this->regexp, $cookieParams[$this->cookie], $matches)) {
            return array_key_exists(1, $matches) ? $matches[1] : null;
        }

        return $cookieParams[$this->cookie];
    }

    #[Override]
    public function name(): string
    {
        return 'cookie';
    }
}
