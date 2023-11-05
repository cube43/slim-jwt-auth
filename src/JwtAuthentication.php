<?php

declare(strict_types=1);

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

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (! $this->isConfigurationSecure($request)) {
            throw new RuntimeException(sprintf(
                'Insecure use of middleware over %s denied by configuration.',
                strtoupper($request->getUri()->getScheme()),
            ));
        }

        try {
            $token = $this->fetchToken->__invoke($request);
        } catch (TokenNotFound) {
            return $handler->handle($request);
        }

        try {
            $jwtDecodedToken = $this->decodeToken->__invoke($token);
        } catch (UnableToDecodeToken) {
            return $handler->handle($request);
        }

        $request = $this->options->before->__invoke(
            $request->withAttribute($this->options->attribute, $jwtDecodedToken),
            $jwtDecodedToken,
        );

        return $this->options->after->__invoke($handler->handle($request), $jwtDecodedToken);
    }

    /**
     * HTTP allowed only if secure is false or server is in relaxed array.
     */
    private function isConfigurationSecure(ServerRequestInterface $request): bool
    {
        if ($request->getUri()->getScheme() === 'https') {
            return true;
        }

        if ($this->options->secure === false) {
            return true;
        }

        return in_array($request->getUri()->getHost(), $this->options->relaxed);
    }
}
