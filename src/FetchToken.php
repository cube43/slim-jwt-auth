<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

use function array_key_exists;
use function is_string;
use function preg_match;

/**
 * @internal
 */
final class FetchToken
{
    public function __construct(
        private readonly JwtAuthenticationOption $options,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Fetch the access token.
     *
     * @return non-empty-string
     */
    public function __invoke(ServerRequestInterface $request): string
    {
        /* Check for token in header. */
        $header = $request->getHeaderLine($this->options->header);

        if (empty($header) === false) {
            if (preg_match($this->options->regexp, $header, $matches)) {
                $this->logger->debug('Using token from request header');

                return $this->produceNonEmptyString($matches[1]);
            }
        }

        /* Token not found in header try a cookie. */
        $cookieParams = $request->getCookieParams();

        if (array_key_exists($this->options->cookie, $cookieParams) && is_string($cookieParams[$this->options->cookie])) {
            $this->logger->debug('Using token from cookie');
            if (preg_match($this->options->regexp, $cookieParams[$this->options->cookie], $matches)) {
                return $this->produceNonEmptyString($matches[1]);
            }

            return $this->produceNonEmptyString($cookieParams[$this->options->cookie]);
        }

        /* If everything fails log and throw. */
        $this->logger->debug('Token not found');

        throw TokenNotFound::create();
    }

    /** @return non-empty-string */
    private function produceNonEmptyString(string $value): string
    {
        if (empty($value)) {
            throw TokenNotFound::create();
        }

        return $value;
    }
}
