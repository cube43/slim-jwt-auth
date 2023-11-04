<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Tuupola\Middleware\JwtAuthentication\NullAclError;
use Tuupola\Middleware\JwtAuthentication\NullAfterHandler;
use Tuupola\Middleware\JwtAuthentication\NullBeforeHandler;

class JwtAuthenticationOption
{
    /**
     * @param string[]         $relaxed
     * @param non-empty-string $regexp
     */
    private function __construct(
        public readonly Key $secret,
        public readonly bool $secure,
        public readonly array $relaxed,
        public readonly Signer $algorithm,
        public readonly string $header,
        public readonly string $regexp,
        public readonly string $cookie,
        public readonly string $attribute,
        public readonly JwtAuthentificationBeforeHandler $before,
        public readonly JwtAuthentificationAfterHandler $after,
        public readonly JwtAuthentificationAclError $error
    ) {
    }

    public static function create(Key $secret): self
    {
        return new self(
            $secret,
            true,
            ['localhost', '127.0.0.1'],
            new Signer\Hmac\Sha256(),
            'Authorization',
            '/Bearer\s+(.*)$/i',
            'token',
            'token',
            new NullBeforeHandler(),
            new NullAfterHandler(),
            new NullAclError(),
        );
    }

    /**
     * Set the attribute name used to attach decoded token to request.
     */
    public function withAttribute(string $attribute): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set the header where token is searched from.
     */
    public function withHeader(string $header): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set the regexp used to extract token from header or environment.
     *
     * @param non-empty-string $regexp
     */
    public function withRegexp(string $regexp): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set the allowed algorithm
     */
    public function withAlgorithm(Signer $algorithm): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set the before handler.
     */
    public function withBefore(JwtAuthentificationBeforeHandler $before): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set the after handler.
     */
    public function withAfter(JwtAuthentificationAfterHandler $after): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $after,
            $this->error,
        );
    }

    /**
     * Set the error handler.
     */
    public function withError(JwtAuthentificationAclError $error): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $error,
        );
    }

    /**
     * Set the cookie name where to search the token from.
     */
    public function withCookie(string $cookie): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set the secure flag.
     */
    public function withSecure(bool $secure): self
    {
        return new self(
            $this->secret,
            $secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set hosts where secure rule is relaxed.
     *
     * @param string[] $relaxed
     */
    public function withRelaxed(array $relaxed): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }

    /**
     * Set the secret key.
     */
    public function withSecret(Key $secret): self
    {
        return new self(
            $secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->before,
            $this->after,
            $this->error,
        );
    }
}
