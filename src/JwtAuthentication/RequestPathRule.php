<?php

declare(strict_types=1);

/*

Copyright (c) 2015-2022 Mika Tuupola

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

/**
 * @see       https://github.com/tuupola/slim-jwt-auth
 * @see       https://appelsiini.net/projects/slim-jwt-auth
 */

namespace Tuupola\Middleware\JwtAuthentication;

use Psr\Http\Message\ServerRequestInterface;

use function preg_match;
use function preg_replace;
use function rtrim;

/**
 * Rule to decide by request path whether the request should be authenticated or not.
 */

final class RequestPathRule implements RuleInterface
{
    /**
     * @param string[] $path
     * @param string[] $ignore
     */
    public function __construct(
        private readonly array $path = ['/'],
        private readonly array $ignore = []
    ) {
    }

    public function __invoke(ServerRequestInterface $request): bool
    {
        $uri = '/' . $request->getUri()->getPath();
        $uri = preg_replace('#/+#', '/', $uri);

        /* If request path is matches ignore should not authenticate. */
        foreach ($this->ignore as $ignore) {
            $ignore = rtrim($ignore, '/');
            if (! ! preg_match("@^{$ignore}(/.*)?$@", (string) $uri)) {
                return false;
            }
        }

        /* Otherwise check if path matches and we should authenticate. */
        foreach ($this->path as $path) {
            $path = rtrim($path, '/');
            if (! ! preg_match("@^{$path}(/.*)?$@", (string) $uri)) {
                return true;
            }
        }

        return false;
    }
}
