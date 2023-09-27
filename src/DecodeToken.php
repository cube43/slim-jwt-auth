<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token\Plain;
use Psr\Log\LoggerInterface;
use Throwable;

final class DecodeToken
{
    public function __construct(
        private readonly ParserInterface $parser,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Decode the token.
     *
     * @param non-empty-string $token
     */
    public function __invoke(string $token): JwtDecodedToken
    {
        try {
            $tokenDecoded = $this->parser->parse($token);

            if ($tokenDecoded->isExpired(new DateTimeImmutable())) {
                throw new Exception('Token expired');
            }

            if (! ($tokenDecoded instanceof Plain)) {
                throw new Exception('Token not signed');
            }
        } catch (Throwable $exception) {
            $this->logger->warning($exception->getMessage(), [$token]);

            throw $exception;
        }

        return new JwtDecodedToken($tokenDecoded, $token);
    }
}
