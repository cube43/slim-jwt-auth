<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Override;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthenticationOption;

use function array_key_exists;
use function is_string;
use function preg_match;

final readonly class FetchTokenFormCookie implements FetchTokenMethod
{
    public function __construct(private JwtAuthenticationOption $options)
    {
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): null|string
    {
        $cookieParams = $request->getCookieParams();

        if (! array_key_exists($this->options->cookie, $cookieParams) || ! is_string($cookieParams[$this->options->cookie])) {
            return null;
        }

        $matches = null;

        if (preg_match($this->options->regexp, $cookieParams[$this->options->cookie], $matches)) {
            return array_key_exists(1, $matches) ? $matches[1] : null;
        }

        return $cookieParams[$this->options->cookie];
    }

    #[Override]
    public function name(): string
    {
        return 'cookie';
    }
}
