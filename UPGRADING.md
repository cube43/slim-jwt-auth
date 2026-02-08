# Upgrading from 6.x to 7.x

La version 7.x introduit des changements majeurs dans l'architecture du middleware, passant d'une configuration basée sur des tableaux à des objets typés, et séparant la logique d'authentification de la logique de pare-feu (Firewall).

## 1. Configuration via `JwtAuthenticationOption`

L'ancienne configuration via un tableau (array) passé au constructeur est remplacée par l'utilisation de la classe `Tuupola\Middleware\JwtAuthenticationOption`.

**Avant (6.x) :**
```php
$app->add(new JwtAuthentication([
    "secret" => "supersecret",
    "tokenAttributeName" => "jwt",
    "secure" => true,
]));
```

**Après (7.x) :**
```php
use Tuupola\Middleware\JwtAuthenticationOption;
use Lcobucci\JWT\Signer\Key\InMemory;

$options = JwtAuthenticationOption::create(InMemory::plainText('supersecret'))
    ->withTokenAttributeName('jwt')
    ->withSecure(true);
```

Notez l'utilisation de `Lcobucci\JWT\Signer\Key\InMemory` pour définir la clé secrète.

## 2. Séparation du Middleware

Le middleware a été scindé en deux parties distinctes :

1. **`JwtAuthentication`** : Responsable uniquement de l'extraction, du décodage et de la validation du token. Il n'interrompt pas la requête si le token est manquant (sauf erreur de décodage critique).
2. **`JwtAuthentificationFirewall`** : Responsable de bloquer les requêtes non authentifiées (401) selon des règles définies.

Vous devez désormais instancier et ajouter ces deux middlewares (le Firewall en premier pour protéger, ou selon votre logique de stack).

```php
use Tuupola\Middleware\JwtAuthentication;
use Tuupola\Middleware\JwtAuthentificationFirewall;
use Laminas\Diactoros\Response; // Une implémentation de PSR-7 Response est requise

// 1. Créer les options
$options = JwtAuthenticationOption::create(InMemory::plainText('secret'));

// 2. Ajouter le Firewall (bloque si pas de token valide)
$app->add(new JwtAuthentificationFirewall($options, new Response()));

// 3. Ajouter l'Authentification (décode le token)
$app->add(JwtAuthentication::create($options));
```

## 3. Règles de chemin (Path) et d'exclusion (Ignore)

Les options `path` et `ignore` ne font plus partie de la configuration principale. Elles sont désormais gérées par des règles (`Rule`) passées au constructeur du `JwtAuthentificationFirewall`.

**Avant (6.x) :**
```php
new JwtAuthentication([
    "path" => ["/api", "/admin"],
    "ignore" => ["/api/login"],
]);
```

**Après (7.x) :**
```php
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

// Premier argument : paths, Second argument : ignore
$pathRule = new RequestPathRule(["/api", "/admin"], ["/api/login"]);

$app->add(new JwtAuthentificationFirewall($options, new Response(), $pathRule));
```

Pour ignorer certaines méthodes HTTP (comme `OPTIONS`), utilisez `IgnoreHttpMethodRule` :

```php
use Tuupola\Middleware\JwtAuthentication\IgnoreHttpMethodRule;

$methodRule = new IgnoreHttpMethodRule(["OPTIONS"]);
$app->add(new JwtAuthentificationFirewall($options, new Response(), $pathRule, $methodRule));
```

## 4. Gestionnaires (Handlers) : Before, After, Unauthorized

Les callbacks sont maintenant définis via des méthodes fluides sur l'objet `JwtAuthenticationOption` et doivent implémenter des interfaces spécifiques (`JwtAuthentificationBeforeHandler`, `JwtAuthentificationAfterHandler`, `JwtAuthentificationUnAuthorizedHandler`). L'option `error` est renommée `unauthorized`.

**Exemple pour `unauthorized` (anciennement `error`) :**

```php
$options = JwtAuthenticationOption::create($key)
    ->withUnAuthorized(new class implements JwtAuthentificationUnAuthorizedHandler {
        public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
        {
            $response->getBody()->write('Unauthorized');
            return $response->withHeader('Content-Type', 'text/plain');
        }
    });
```
