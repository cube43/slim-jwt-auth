<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Override;
use Psr\Http\Message\ServerRequestInterface;

use function in_array;

final readonly class AllowedInsecureHosts implements JwtAuthentificationSecurity
{
    /** @param string[] $allowedInsecureHosts */
    public function __construct(public array $allowedInsecureHosts)
    {
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): bool
    {
        if ($request->getUri()->getScheme() === 'https') {
            return true;
        }

        return in_array($request->getUri()->getHost(), $this->allowedInsecureHosts);
    }
}
