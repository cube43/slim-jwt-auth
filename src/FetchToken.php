<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Tuupola\Middleware\JwtAuthentication\FetchTokenMethod;

use function sprintf;

/** @internal */
final readonly class FetchToken
{
    /** @var FetchTokenMethod[] */
    private readonly array $fetchTokenMethods;

    public function __construct(
        private LoggerInterface $logger,
        FetchTokenMethod ...$fetchTokenMethods
    ) {
        $this->fetchTokenMethods = $fetchTokenMethods;
    }

    /**
     * Fetch the access token.
     *
     * @return non-empty-string
     *
     * @throw TokenNotFound
     */
    public function __invoke(ServerRequestInterface $request): string
    {
        foreach ($this->fetchTokenMethods as $fetchTokenMethod) {
            $token = self::produceNonEmptyString($fetchTokenMethod->__invoke($request));

            if ($token !== null) {
                $this->logger->debug(sprintf('Using token from %s', $fetchTokenMethod->name()));

                return $token;
            }
        }

        /* If everything fails log and throw. */
        $this->logger->debug('Token not found');

        throw TokenNotFound::create();
    }

    /** @return non-empty-string|null */
    private static function produceNonEmptyString(string|null $value): string|null
    {
        return $value === '' || $value === null ? null : $value;
    }
}
