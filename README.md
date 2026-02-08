# Slim JWT Auth

[![Build Status](https://github.com/cube43/slim-jwt-auth/actions/workflows/continuous-integration.yml/badge.svg)](https://github.com/cube43/slim-jwt-auth/actions/workflows/continuous-integration.yml)
[![Type Coverage](https://shepherd.dev/github/cube43/slim-jwt-auth/coverage.svg)](https://shepherd.dev/github/cube43/slim-jwt-auth)
[![Type Coverage](https://shepherd.dev/github/cube43/slim-jwt-auth/level.svg)](https://shepherd.dev/github/cube43/slim-jwt-auth)
[![Latest Stable Version](https://poser.pugx.org/cube43/slim-jwt-auth/v/stable)](https://packagist.org/packages/cube43/slim-jwt-auth)
[![License](https://poser.pugx.org/cube43/slim-jwt-auth/license)](https://packagist.org/packages/cube43/slim-jwt-auth)

PSR-7 and PSR-15 Middleware for JWT Authentication. This is a strict-typed, modern rewrite of the popular JWT middleware, designed for Slim Framework and other PSR-15 compliant frameworks.

## Installation

Install via Composer:

```bash
composer require cube43/slim-jwt-auth
```

## Usage

This library splits the JWT logic into two separate middlewares to provide better flexibility:

1.  **`JwtAuthentication`**: Parses and validates the token. If valid, it attaches the decoded token to the request tokenAttributeNames. It does **not** block the request if the token is missing (it acts as a hydrator).
2.  **`JwtAuthentificationFirewall`**: Checks if the request requires authentication (based on rules). If it does, and no valid token was found by the previous middleware, it returns a 401 Unauthorized response.

### Complete Example

Here is a complete example setup for Slim 4, including custom handlers and rules:

```php
use Slim\Factory\AppFactory;
use Tuupola\Middleware\JwtAuthentication;
use Tuupola\Middleware\JwtAuthenticationOption;
use Tuupola\Middleware\JwtAuthentificationFirewall;
use Tuupola\Middleware\JwtAuthentication\FetchTokenFormHeader;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;
use Tuupola\Middleware\JwtAuthentificationUnAuthorizedHandler;
use Tuupola\Middleware\JwtAuthentificationBeforeHandler;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Laminas\Diactoros\Response;
use Throwable;

$app = AppFactory::create();

// 1. Configure Options
$options = JwtAuthenticationOption::create(InMemory::plainText('super-secret-key'))
    ->withTokenAttributeName('jwt')
    ->withAllowedInsecureHosts(['localhost', '127.0.0.1'])
    ->withBeforeHandleRequestWhenTokenAvailable(new class implements JwtAuthentificationBeforeHandler {
        public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface
        {
            assert($request->getAttribute('jwt') === $token);
            return $request->withAttribute('user_uuid', $token->claims()->get('uuid'));
        }
    });

// 2. Define Rules (e.g. protect /api, but allow /api/login)
$pathRule = new RequestPathRule(
    path: ['/api'],
    ignore: ['/api/login', '/api/token']
);

// 3. Define Unauthorized Handler (JSON response)
$unauthorizedHandler = new class implements JwtAuthentificationUnAuthorizedHandler {
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
    {
        $response->getBody()->write(json_encode(['status' => 'error', 'message' => 'Unauthorized']));
        return $response->withHeader('Content-Type', 'application/json');
    }
};

// 4. Add Middleware (LIFO: Add Firewall first, then Authentication)

// Firewall: Checks rules and blocks if no token is present when required
// It runs LAST in the stack (executed AFTER Authentication)
$app->add(new JwtAuthentificationFirewall(
    $options,
    new Response(),
    $unauthorizedHandler,
    $pathRule
));

// Authentication: Extracts and decodes token
// It runs FIRST in the stack (executed BEFORE Firewall)
$app->add(JwtAuthentication::create(
    $options,
    new FetchTokenFormHeader()
));

$app->run();
```

> **Important:** In Slim, middleware is executed Last-In-First-Out. You must ensure `JwtAuthentication` runs **before** `JwtAuthentificationFirewall` so the token is available when the firewall checks for it.

### Configuration Options

The `JwtAuthenticationOption` class uses a fluent interface for configuration.

```php
$options = JwtAuthenticationOption::create(InMemory::plainText('secret'))
    ->withTokenAttributeName('jwt')       // Attribute name for the decoded token
    ->withEnforceHttps(true)           // Require HTTPS
    ->withAllowedInsecureHosts(['localhost']); // Allow HTTP on these hosts
```

### Token Extraction

You define how the token is extracted when creating the `JwtAuthentication` middleware. You can pass multiple extractors.

```php
use Tuupola\Middleware\JwtAuthentication\FetchTokenFormHeader;
use Tuupola\Middleware\JwtAuthentication\FetchTokenFormCookie;

$app->add(JwtAuthentication::create(
    $options,
    new FetchTokenFormHeader('Authorization', '/Bearer\s+(.*)$/i'),
    new FetchTokenFormCookie('auth_token')
));
```

### Firewall Rules

To define which requests require authentication, pass `RuleInterface` implementations to the `JwtAuthentificationFirewall` constructor.

#### Path Rule
Restrict authentication to specific paths, or ignore specific paths.

```php
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

// Authenticate everything under /api, but ignore /api/login
$pathRule = new RequestPathRule(
    path: ['/api'],
    ignore: ['/api/login']
);

$app->add(new JwtAuthentificationFirewall(
    $options,
    $response,
    new NullUnAuthorizedHandler(), // Default handler
    $pathRule
));
```

#### Method Rule
Ignore specific HTTP methods (e.g., OPTIONS).

```php
use Tuupola\Middleware\JwtAuthentication\IgnoreHttpMethodRule;

$methodRule = new IgnoreHttpMethodRule(['OPTIONS']);

$app->add(new JwtAuthentificationFirewall(
    $options,
    $response,
    new NullUnAuthorizedHandler(),
    $pathRule,
    $methodRule
));
```

### Handlers

You can customize behavior using handlers.

#### Before Handler
Modify the request after the token is decoded but before the next middleware.

```php
use Tuupola\Middleware\JwtAuthentificationBeforeHandler;
use Lcobucci\JWT\Token\Plain;

$options = $options->withBeforeHandleRequestWhenTokenAvailable(new class implements JwtAuthentificationBeforeHandler {
    public function __invoke(ServerRequestInterface $request, Plain $token): ServerRequestInterface
    {
        assert($request->getAttribute('jwt') === $token);
        return $request->withAttribute('user_id', $token->claims()->get('uid'));
    }
});
```

#### After Handler
Modify the response before returning it.

```php
use Tuupola\Middleware\JwtAuthentificationAfterHandler;

$options = $options->withAfterHandleRequestWhenTokenAvailable(new class implements JwtAuthentificationAfterHandler {
    public function __invoke(ResponseInterface $response, Plain $token): ResponseInterface
    {
        return $response->withHeader('X-Auth-Success', 'true');
    }
});
```

#### Unauthorized Handler
Customize the response when authentication fails (used by the Firewall).

```php
use Tuupola\Middleware\JwtAuthentificationUnAuthorizedHandler;

$firewall = new JwtAuthentificationFirewall(
    $options,
    $response,
    new class implements JwtAuthentificationUnAuthorizedHandler {
        public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
        {
            $response->getBody()->write(json_encode(['error' => 'Unauthorized']));
            return $response->withHeader('Content-Type', 'application/json');
        }
    }
);
```

## Security

By default, the middleware throws a `RuntimeException` if you attempt to use it over HTTP (insecure). To allow HTTP for development, use `withAllowedInsecureHosts`:

```php
$options = $options->withAllowedInsecureHosts(['localhost', '127.0.0.1']);
```
