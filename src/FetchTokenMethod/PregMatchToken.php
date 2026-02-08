<?php

declare(strict_types=1);

namespace Tuupola\Middleware\FetchTokenMethod;

use SensitiveParameter;

use function array_key_exists;
use function preg_match;

/** @internal  */
final readonly class PregMatchToken
{
    /** @param non-empty-string $regexp */
    public function __construct(
        #[SensitiveParameter]
        private string $regexp,
    ) {
    }

    public function __invoke(#[SensitiveParameter]
    string $token): null|string
    {
        $matches = [];
        preg_match($this->regexp, $token, $matches);

        return array_key_exists(1, $matches) ? $matches[1] : null;
    }
}
