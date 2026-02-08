<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Override;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthenticationOption;

use function array_key_exists;
use function preg_match;

final readonly class FetchTokenFormHeader implements FetchTokenMethod
{
    public function __construct(private JwtAuthenticationOption $options)
    {
    }

    #[Override]
    public function __invoke(ServerRequestInterface $request): null|string
    {
        $header  = $request->getHeaderLine($this->options->header);
        $matches = null;
        preg_match($this->options->regexp, $header, $matches);

        return array_key_exists(1, $matches) ? $matches[1] : null;
    }

    #[Override]
    public function name(): string
    {
        return 'request header';
    }
}
