<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use DateTimeImmutable;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token\Plain;
use Psr\Log\LoggerInterface;
use Throwable;
use Tuupola\Middleware\Exception\TokenExpired;
use Tuupola\Middleware\Exception\TokenNotSigned;
use Tuupola\Middleware\Exception\UnableToDecodeToken;

final readonly class DecodeToken
{
    public function __construct(
        private ParserInterface $parser,
        private LoggerInterface $logger,
    ) {
    }

    public function withLogger(LoggerInterface $logger): self
    {
        return new self($this->parser, $logger);
    }

    /**
     * Decode the token.
     *
     * @param non-empty-string $token
     *
     * @throw UnableToDecodeToken
     */
    public function __invoke(string $token): Plain
    {
        try {
            $tokenDecoded = $this->parser->parse($token);

            if ($tokenDecoded->isExpired(new DateTimeImmutable())) {
                throw TokenExpired::create();
            }

            if (! ($tokenDecoded instanceof Plain)) {
                throw TokenNotSigned::create();
            }
        } catch (Throwable $exception) {
            $this->logger->warning($exception->getMessage(), ['token' => $token]);

            throw UnableToDecodeToken::create($exception);
        }

        return $tokenDecoded;
    }
}
