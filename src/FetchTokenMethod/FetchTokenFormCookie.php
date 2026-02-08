<?php

declare(strict_types=1);

namespace Tuupola\Middleware\FetchTokenMethod;

use Override;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

use function array_key_exists;
use function is_string;

final readonly class FetchTokenFormCookie implements FetchTokenMethod
{
    private PregMatchToken $pregMatchToken;

    /**
     * @param non-empty-string $cookie
     * @param non-empty-string $regexp
     */
    public function __construct(
        #[SensitiveParameter]
        private string $cookie = 'token',
        #[SensitiveParameter]
        string $regexp = '/Bearer\s+(.*)$/i',
    ) {
        $this->pregMatchToken = new PregMatchToken($regexp);
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): null|string
    {
        $cookieParams = $request->getCookieParams();

        return $this->pregMatchToken->__invoke(
            ! array_key_exists($this->cookie, $cookieParams) || ! is_string($cookieParams[$this->cookie]) ? '' : $cookieParams[$this->cookie],
        );
    }
}
