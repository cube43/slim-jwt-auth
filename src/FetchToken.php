<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Tuupola\Middleware\Exception\TokenNotFound;
use Tuupola\Middleware\FetchTokenMethod\FetchTokenMethod;

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
     */
    public function __invoke(ServerRequestInterface $request): string
    {
        $fetchedToken = $this->getToken($request);

        if ($fetchedToken === null) {
            /* If everything fails log and throw. */
            $this->logger->debug('Token not found');

            throw TokenNotFound::create();
        }

        $this->logger->debug('Using token from', ['class' => $fetchedToken->class]);

        return $fetchedToken->token;
    }

    /** @throw TokenNotFound */
    private function getToken(ServerRequestInterface $request): FetchedToken|null
    {
        foreach ($this->fetchTokenMethods as $fetchTokenMethod) {
            $token = $fetchTokenMethod->__invoke($request);

            if ($token !== '' && $token !== null) {
                return new FetchedToken($token, $fetchTokenMethod::class);
            }
        }

        return null;
    }
}
