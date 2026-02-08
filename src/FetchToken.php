<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Tuupola\Middleware\Exception\TokenNotFound;
use Tuupola\Middleware\FetchTokenMethod\FetchTokenMethod;

use function sprintf;

/** @internal */
final readonly class FetchToken
{
    /** @var FetchTokenMethod[] */
    private array $fetchTokenMethods;

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
            $token = $fetchTokenMethod->__invoke($request);

            if ($token !== '' && $token !== null) {
                $this->logger->debug(sprintf('Using token from %s', $fetchTokenMethod->name()));

                return $token;
            }
        }

        /* If everything fails log and throw. */
        $this->logger->debug('Token not found');

        throw TokenNotFound::create();
    }
}
