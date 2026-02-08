<?php

declare(strict_types=1);

namespace Tuupola\Middleware\Middleware;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Tuupola\Middleware\Exception\NotAuthorized;
use Tuupola\Middleware\JwtAuthenticationOption;
use Tuupola\Middleware\Rule\RuleInterface;
use Tuupola\Middleware\UnAuthorizedHandler\JwtAuthentificationUnAuthorizedHandler;
use Tuupola\Middleware\UnAuthorizedHandler\NullUnAuthorizedHandler;

use function array_all;

final readonly class JwtAuthentificationFirewall implements MiddlewareInterface
{
    /** @var RuleInterface[] */
    private array $rules;

    public function __construct(
        private JwtAuthenticationOption $options,
        private ResponseInterface $response,
        private JwtAuthentificationUnAuthorizedHandler $unAuthorizedHandler = new NullUnAuthorizedHandler(),
        RuleInterface ...$rules
    ) {
        $this->rules = $rules;
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (! $this->shouldAuthenticate($request)) {
            return $handler->handle($request);
        }

        if ($request->getAttribute($this->options->tokenAttributeName) === null) {
            return $this->unAuthorizedHandler->__invoke($request, $this->response->withStatus(401), NotAuthorized::create());
        }

        return $handler->handle($request);
    }

    private function shouldAuthenticate(ServerRequestInterface $request): bool
    {
        return array_all($this->rules, static fn ($callable) => $callable($request));
    }
}
