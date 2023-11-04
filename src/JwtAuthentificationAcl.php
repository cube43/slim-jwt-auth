<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Tuupola\Middleware\JwtAuthentication\RuleInterface;

final class JwtAuthentificationAcl implements MiddlewareInterface
{
    /** @var RuleInterface[] */
    private array $rules;

    public function __construct(
        private readonly JwtAuthenticationOption $options,
        private readonly ResponseInterface $response,
        RuleInterface ...$rules
    ) {
        $this->rules = $rules;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->shouldAuthenticate($request) === false) {
            return $handler->handle($request);
        }

        if ($request->getAttribute($this->options->attribute) === null) {
            return $this->options->error->__invoke($request, $this->response->withStatus(401), NotAuthorized::create());
        }

        return $handler->handle($request);
    }

    private function shouldAuthenticate(ServerRequestInterface $request): bool
    {
        foreach ($this->rules as $callable) {
            if (! $callable($request)) {
                return false;
            }
        }

        return true;
    }
}
