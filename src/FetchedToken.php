<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use SensitiveParameter;

/** @internal */
final readonly class FetchedToken
{
    /**
     * @param non-empty-string $token
     * @param non-empty-string $class
     */
    public function __construct(
        #[SensitiveParameter]
        public string $token,
        public string $class,
    ) {
    }
}
