<?php

declare(strict_types=1);

namespace Tuupola\Middleware\Middleware;

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
use Tuupola\Middleware\DecodeToken;
use Tuupola\Middleware\Exception\TokenNotFound;
use Tuupola\Middleware\Exception\UnableToDecodeToken;
use Tuupola\Middleware\FetchToken;
use Tuupola\Middleware\FetchTokenMethod\FetchTokenMethod;
use Tuupola\Middleware\JwtAuthenticationOption;

use function sprintf;
use function strtoupper;

final readonly class JwtAuthentication implements MiddlewareInterface
{
    private FetchToken $fetchToken;
    private DecodeToken $decodeToken;
    /** @var FetchTokenMethod[] */
    private array $fetchTokenMethod;

    private function __construct(
        private JwtAuthenticationOption $options,
        private LoggerInterface $logger,
        DecodeToken $decodeToken,
        FetchTokenMethod ...$fetchTokenMethod
    ) {
        $this->fetchToken       = new FetchToken($logger, ...$fetchTokenMethod);
        $this->decodeToken      = $decodeToken;
        $this->fetchTokenMethod = $fetchTokenMethod;
    }

    public function withLogger(LoggerInterface $logger): self
    {
        return new self($this->options, $logger, $this->decodeToken->withLogger($logger), ...$this->fetchTokenMethod);
    }

    public function withDecodeToken(DecodeToken $decodeToken): self
    {
        return new self($this->options, $this->logger, $decodeToken, ...$this->fetchTokenMethod);
    }

    public static function create(JwtAuthenticationOption $options, FetchTokenMethod ...$fetchTokenMethod): self
    {
        return new self($options, new NullLogger(), new DecodeToken(new Parser(new JoseEncoder()), new NullLogger()), ...$fetchTokenMethod);
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (! $this->options->security->__invoke($request)) {
            throw new RuntimeException(sprintf(
                'Insecure use of middleware over %s denied by configuration.',
                strtoupper($request->getUri()->getScheme()),
            ));
        }

        try {
            $token           = $this->fetchToken->__invoke($request);
            $jwtDecodedToken = $this->decodeToken->__invoke($token);
        } catch (TokenNotFound | UnableToDecodeToken) {
            return $handler->handle($request);
        }

        $request  = $request->withAttribute($this->options->tokenAttributeName, $jwtDecodedToken);
        $request  = $this->options->beforeHandleRequestWhenTokenAvailable->__invoke($request, $jwtDecodedToken);
        $response = $handler->handle($request);

        return $this->options->afterHandleRequestWhenTokenAvailable->__invoke($response, $jwtDecodedToken);
    }
}
