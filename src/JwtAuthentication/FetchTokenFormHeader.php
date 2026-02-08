<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Override;
use Psr\Http\Message\ServerRequestInterface;

use function array_key_exists;
use function preg_match;

final readonly class FetchTokenFormHeader implements FetchTokenMethod
{
    /**
     * @param non-empty-string $header
     * @param non-empty-string $regexp
     */
    public function __construct(
        private string $header = 'Authorization',
        private string $regexp = '/Bearer\s+(.*)$/i',
    ) {
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): null|string
    {
        $header  = $request->getHeaderLine($this->header);
        $matches = null;
        preg_match($this->regexp, $header, $matches);

        return array_key_exists(1, $matches) ? $matches[1] : null;
    }

    #[Override]
    public function name(): string
    {
        return 'request header';
    }
}
