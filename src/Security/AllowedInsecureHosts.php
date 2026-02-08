<?php

declare(strict_types=1);

namespace Tuupola\Middleware\Security;

use Override;
use Psr\Http\Message\ServerRequestInterface;
use SensitiveParameter;

use function in_array;

final readonly class AllowedInsecureHosts implements JwtAuthentificationSecurity
{
    /** @param string[] $allowedInsecureHosts */
    public function __construct(#[SensitiveParameter]
    private array $allowedInsecureHosts)
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
