<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Lcobucci\JWT\Signer\Key;
use Tuupola\Middleware\AfterHandler\JwtAuthentificationAfterHandler;
use Tuupola\Middleware\AfterHandler\NullAfterHandler;
use Tuupola\Middleware\BeforeHandler\JwtAuthentificationBeforeHandler;
use Tuupola\Middleware\BeforeHandler\NullBeforeHandler;
use Tuupola\Middleware\Security\AllowedInsecureHosts;
use Tuupola\Middleware\Security\JwtAuthentificationSecurity;

final readonly class JwtAuthenticationOption
{
    private function __construct(
        public Key $secret,
        public JwtAuthentificationSecurity $security,
        public string $tokenAttributeName,
        public JwtAuthentificationBeforeHandler $beforeHandleRequestWhenTokenAvailable,
        public JwtAuthentificationAfterHandler $afterHandleRequestWhenTokenAvailable,
    ) {
    }

    public static function create(Key $secret): self
    {
        return new self(
            $secret,
            new AllowedInsecureHosts(['localhost', '127.0.0.1']),
            'token',
            new NullBeforeHandler(),
            new NullAfterHandler(),
        );
    }

    /**
     * Set the tokenAttributeName name used to attach decoded token to request.
     */
    public function withTokenAttributeName(string $tokenAttributeName): self
    {
        return new self(
            $this->secret,
            $this->security,
            $tokenAttributeName,
            $this->beforeHandleRequestWhenTokenAvailable,
            $this->afterHandleRequestWhenTokenAvailable,
        );
    }

    /**
     * Set the before handler.
     */
    public function withBeforeHandleRequestWhenTokenAvailable(JwtAuthentificationBeforeHandler $beforeHandleRequestWhenTokenAvailable): self
    {
        return new self(
            $this->secret,
            $this->security,
            $this->tokenAttributeName,
            $beforeHandleRequestWhenTokenAvailable,
            $this->afterHandleRequestWhenTokenAvailable,
        );
    }

    /**
     * Set the after handler.
     */
    public function withAfterHandleRequestWhenTokenAvailable(JwtAuthentificationAfterHandler $afterHandleRequestWhenTokenAvailable): self
    {
        return new self(
            $this->secret,
            $this->security,
            $this->tokenAttributeName,
            $this->beforeHandleRequestWhenTokenAvailable,
            $afterHandleRequestWhenTokenAvailable,
        );
    }

    /**
     * Set the secure flag.
     */
    public function withSecurity(JwtAuthentificationSecurity $security): self
    {
        return new self(
            $this->secret,
            $security,
            $this->tokenAttributeName,
            $this->beforeHandleRequestWhenTokenAvailable,
            $this->afterHandleRequestWhenTokenAvailable,
        );
    }

    /**
     * Set the secret key.
     */
    public function withSecret(Key $secret): self
    {
        return new self(
            $secret,
            $this->security,
            $this->tokenAttributeName,
            $this->beforeHandleRequestWhenTokenAvailable,
            $this->afterHandleRequestWhenTokenAvailable,
        );
    }
}
