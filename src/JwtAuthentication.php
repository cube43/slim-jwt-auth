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

namespace Tuupola\Middleware;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token\Parser;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Throwable;

use function in_array;
use function sprintf;
use function strtoupper;

final class JwtAuthentication implements MiddlewareInterface
{
    private readonly FetchToken $fetchToken;
    private readonly DecodeToken $decodeToken;

    public function __construct(
        private readonly JwtAuthenticationOption $options,
        ?LoggerInterface $logger = null,
        ?ParserInterface $parser = null
    ) {
        $logger          ??= new NullLogger();
        $this->fetchToken  = new FetchToken($options, $logger);
        $this->decodeToken = new DecodeToken($parser ?? new Parser(new JoseEncoder()), $logger);
    }

    /**
     * Process a request in PSR-15 style and return a response.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $scheme = $request->getUri()->getScheme();
        $host   = $request->getUri()->getHost();

        /* HTTP allowed only if secure is false or server is in relaxed array. */
        if ($scheme !== 'https' && $this->options->secure === true && ! in_array($host, $this->options->relaxed)) {
            throw new RuntimeException(sprintf(
                'Insecure use of middleware over %s denied by configuration.',
                strtoupper($scheme),
            ));
        }

        try {
            $token = $this->fetchToken->__invoke($request);
        } catch (TokenNotFound) {
            return $handler->handle($request);
        }

        try {
            $jwtDecodedToken = $this->decodeToken->__invoke($token);
        } catch (Throwable) {
            return $handler->handle($request);
        }

        /* Add decoded token to request as attribute when requested. */
        $request = $request->withAttribute($this->options->attribute, $jwtDecodedToken);

        /* Modify $request before calling next middleware. */
        $request = $this->options->before->__invoke($request, $jwtDecodedToken);

        /* Everything ok, call next middleware. */
        $response = $handler->handle($request);

        /* Modify $response before returning. */
        return $this->options->after->__invoke($response, $jwtDecodedToken);
    }
}
