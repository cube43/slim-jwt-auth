<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Tuupola\Middleware\JwtAuthentication\NullAfterHandler;
use Tuupola\Middleware\JwtAuthentication\NullBeforeHandler;
use Tuupola\Middleware\JwtAuthentication\NullUnAuthorizedHandler;

final readonly class JwtAuthenticationOption
{
    /**
     * @param string[]         $relaxed
     * @param non-empty-string $regexp
     */
    private function __construct(
        public Key $secret,
        public bool $secure,
        public array $relaxed,
        public Signer $algorithm,
        public string $header,
        public string $regexp,
        public string $cookie,
        public string $attribute,
        public JwtAuthentificationBeforeHandler $before,
        public JwtAuthentificationAfterHandler $after,
        public JwtAuthentificationUnAuthorizedHandler $unAuthorizedHandler,
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
            new NullUnAuthorizedHandler(),
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
        );
    }

    /**
     * Set the error handler.
     */
    public function withUnAuthorized(JwtAuthentificationUnAuthorizedHandler $unAuthorized): self
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
            $unAuthorized,
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
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
            $this->unAuthorizedHandler,
        );
    }
}
