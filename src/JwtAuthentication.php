<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Tuupola\Middleware\JwtAuthentication\FetchTokenFormCookie;
use Tuupola\Middleware\JwtAuthentication\FetchTokenFormHeader;

use function in_array;
use function sprintf;
use function strtoupper;

final readonly class JwtAuthentication implements MiddlewareInterface
{
    private FetchToken $fetchToken;
    private DecodeToken $decodeToken;

    private function __construct(
        private JwtAuthenticationOption $options,
        private LoggerInterface $logger,
        DecodeToken $decodeToken,
    ) {
        $this->fetchToken  = new FetchToken($logger, new FetchTokenFormHeader($options), new FetchTokenFormCookie($options));
        $this->decodeToken = $decodeToken;
    }

    public function withLogger(LoggerInterface $logger): self
    {
        return new self($this->options, $logger, $this->decodeToken->withLogger($logger));
    }

    public function withDecodeToken(DecodeToken $decodeToken): self
    {
        return new self($this->options, $this->logger, $decodeToken);
    }

    public static function create(JwtAuthenticationOption $options): self
    {
        return new self($options, new NullLogger(), new DecodeToken(new Parser(new JoseEncoder()), new NullLogger()));
    }

    #[Override]
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

        if (! $this->options->secure) {
            return true;
        }

        return in_array($request->getUri()->getHost(), $this->options->relaxed);
    }
}
