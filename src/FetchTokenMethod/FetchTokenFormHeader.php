<?php

declare(strict_types=1);

namespace Tuupola\Middleware\FetchTokenMethod;

use Override;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

final readonly class FetchTokenFormHeader implements FetchTokenMethod
{
    private PregMatchToken $pregMatchToken;

    /**
     * @param non-empty-string $header
     * @param non-empty-string $regexp
     */
    public function __construct(
        #[SensitiveParameter]
        private string $header = 'Authorization',
        #[SensitiveParameter]
        string $regexp = '/Bearer\s+(.*)$/i',
    ) {
        $this->pregMatchToken = new PregMatchToken($regexp);
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): null|string
    {
        return $this->pregMatchToken->__invoke($request->getHeaderLine($this->header));
    }
}
