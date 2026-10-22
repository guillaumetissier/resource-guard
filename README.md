# guillaumetissier/resource-guard

Protects an API with the access tokens of [Auth Server](https://github.com/guillaumetissier/auth-server)
(other servers issuing RS256 JWT access tokens with the same claims and a JWKS endpoint work too):

- validates the JWT access tokens offline, with the server's JWKS (RS256 only, expiry, audience allow-list);
- validates DPoP proofs (RFC 9449): signature, `htm`, `htu`, `iat` window, `ath`, key binding (`cnf.jkt`), replay;
- exposes who is calling, including impersonation details, and refuses writes during read-only impersonations;
- checks the caller's rights per resource type and domain, from the `dom` / `acl` claims;
- verifies the signed webhooks of the server.

The core is framework-agnostic. Adapters are provided for **Laravel**, **Symfony** and **PSR-15**.

```bash
composer require guillaumetissier/resource-guard
```

Requirements: PHP 8.3+, `ext-openssl`.

## Laravel

The service provider is auto-discovered. Publish the configuration if you need to change more than the
environment variables:

```bash
php artisan vendor:publish --tag=resource-guard-config
```

```dotenv
AUTH_SERVER_JWKS_URI=http://auth-server:8080/.well-known/jwks.json
AUTH_SERVER_ALLOWED_CLIENTS=my-spa              # optional allow-list of OAuth clients
AUTH_SERVER_REQUIRE_DPOP=true                   # refuse plain Bearer tokens
AUTH_SERVER_CACHE_STORE=redis                   # must be shared by all workers (DPoP replay protection)
AUTH_SERVER_USER_MODEL="App\Models\User"        # set as the authenticated user, found by the token "sub"
AUTH_SERVER_WEBHOOK_SECRET=<same value as WEBHOOK_SECRET on the server>
```

```php
Route::middleware('auth.oauth')->get('/api/items', ...);                       // any valid token
Route::middleware('auth.oauth:items.read,items.write')->post('/api/items', ...); // every listed scope required
Route::middleware('auth.oauth:no-impersonation')->post('/api/password', ...);   // never while impersonated
```

In a controller:

```php
$principal = $request->attributes->get('oauth_principal');   // GuillaumeTissier\ResourceGuard\Guard\Principal
$principal->userId;            // the token "sub": the user's id in your database
$principal->scopes;
$principal->isImpersonated();  // an administrator acts on behalf of the user
$principal->actorId();         // that administrator's id: record it in your audit trail
auth()->user();                // the Eloquent user, when AUTH_SERVER_USER_MODEL is set
```

Webhooks are received on `POST /auth-server/webhook` (configurable) and re-dispatched as Laravel events:

```php
use GuillaumeTissier\ResourceGuard\Bridge\Laravel\AuthServerEventReceived;
use GuillaumeTissier\ResourceGuard\Webhook\WebhookEvent;

Event::listen(AuthServerEventReceived::class, function (AuthServerEventReceived $e) {
    if ($e->event->type === WebhookEvent::USER_LOCKED) {
        // $e->event->userId(), $e->event->data
    }
});
```

## Symfony

Requires `symfony/http-client` and `nyholm/psr7`.

```yaml
# config/services.yaml
services:
    resource_guard.cache:
        class: Symfony\Component\Cache\Psr16Cache
        arguments: ['@cache.app']
    GuillaumeTissier\ResourceGuard\Token\JwksProviderInterface:
        class: GuillaumeTissier\ResourceGuard\Token\HttpJwksProvider
        arguments: ['%env(AUTH_SERVER_JWKS_URI)%', '@psr18.http_client', '@psr18.http_client', '@resource_guard.cache']
    GuillaumeTissier\ResourceGuard\Dpop\ReplayStoreInterface:
        class: GuillaumeTissier\ResourceGuard\Dpop\Psr16ReplayStore
        arguments: ['@resource_guard.cache']
    GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator: ~
    GuillaumeTissier\ResourceGuard\Token\AccessTokenValidator: ~
    GuillaumeTissier\ResourceGuard\Guard\ResourceGuard: ~
    GuillaumeTissier\ResourceGuard\Bridge\Symfony\ResourceGuardAuthenticator: ~
    GuillaumeTissier\ResourceGuard\Webhook\WebhookSignature:
        arguments: ['%env(AUTH_SERVER_WEBHOOK_SECRET)%']
    GuillaumeTissier\ResourceGuard\Bridge\Symfony\WebhookController:
        tags: ['controller.service_arguments']
        arguments: { $cache: '@resource_guard.cache' }
```

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            provider: app_user_provider            # loads users by the token "sub"
            custom_authenticators: [GuillaumeTissier\ResourceGuard\Bridge\Symfony\ResourceGuardAuthenticator]
            entry_point: GuillaumeTissier\ResourceGuard\Bridge\Symfony\ResourceGuardAuthenticator
```

The `Principal` is available as the request attribute and the security token attribute `oauth_principal`
(`ResourceGuardAuthenticator::principal($token)`). Route the `WebhookController` yourself, outside any
authenticated firewall, and listen to `AuthServerEventReceived`.

## PSR-15 and other frameworks

```php
use GuillaumeTissier\ResourceGuard\Bridge\Psr15\ResourceGuardMiddleware;
use GuillaumeTissier\ResourceGuard\Dpop\DpopProofValidator;
use GuillaumeTissier\ResourceGuard\Dpop\Psr16ReplayStore;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use GuillaumeTissier\ResourceGuard\Token\AccessTokenValidator;
use GuillaumeTissier\ResourceGuard\Token\HttpJwksProvider;

$guard = new ResourceGuard(
    new AccessTokenValidator(new HttpJwksProvider($jwksUri, $psr18Client, $psr17RequestFactory, $psr16Cache)),
    new DpopProofValidator(new Psr16ReplayStore($psr16Cache)),
);

$app->add(new ResourceGuardMiddleware($guard, $psr17ResponseFactory, $psr17StreamFactory));
// the Principal is the request attribute "oauth_principal"
```

Without any framework, call `$guard->authenticate($method, $absoluteUri, $authorizationHeader, $dpopHeaders)`:
it returns a `Principal` or throws `AuthenticationFailed`, which carries the HTTP status and the
`WWW-Authenticate` header to send back.

## Access control (domains and rights)

When the server uses domains, tokens carry the user's domain and rights:

```json
"dom": "/a1/a10/",
"acl": [["/a1/a10/", true, "*:r vehicle:w"], ["/a1/a10/a100/", false, "invoice:w"], ["/a1/a10/", true, "user:w:own"]]
```

Each entry: domain path, whether it extends to the subdomains, access expression. Check them with the
domain path of the resource (your application knows where each resource belongs):

```php
use GuillaumeTissier\ResourceGuard\Access\AccessLevel;

$principal->can('vehicle', AccessLevel::Write, '/a1/a10/a101/');                     // true: a10 and subdomains
$principal->can('invoice', AccessLevel::Write, '/a1/a10/a101/');                     // false: a100 only
$principal->can('vehicle', AccessLevel::Read, '/a1/a11/');                           // false: outside the user's domain
$principal->can('user', AccessLevel::Write, '/a1/a10/', ownerId: $profile->userId);  // ":own" rules: his own profile
$principal->accessLevel('vehicle', '/a1/a10/');                                      // AccessLevel::Write
$principal->domain();                                                                // "/a1/a10/"
```

Rules of evaluation:

| Expression | Meaning |
|---|---|
| `vehicle:r` | levels `-` none, `r` read, `w` write, `m` manage (`AccessLevel` enum); each includes the lower ones |
| `*:w tire:r` | a named type beats `*`, whatever the order: everything writable, tires read-only |
| `*:r invoice:-` | everything readable except invoices |
| `user:r user:w:own` | `:own` applies to resources owned by the caller (`ownerId` = the token `sub`) |
| `@impersonate:r` | reserved `@` types are never covered by `*` |

- Several entries covering a domain: the highest level wins.
- Nothing ever applies outside the user's domain subtree, even if an entry claims so (fail closed).
- During a read-only impersonation, `accessLevel()` and `can()` never exceed READ.

The same classes (`AccessExpression`, `AccessControlList`, `DomainPath`) work without a token, e.g. to
validate expressions in your own tools.

## Behaviour

| Request | Result |
|---|---|
| No `Authorization` header | 401, `WWW-Authenticate: DPoP algs="…"` |
| `DPoP <token>` + valid proof signed by the bound key | Accepted |
| `DPoP <token>` with a proof from another key, a replayed proof or a proof for another URL | 401 `invalid_dpop_proof` |
| DPoP-bound token sent as `Bearer` | 401 `invalid_token` |
| Plain Bearer token | Accepted only when DPoP is not required |
| Expired token, unknown signature, client not allowed | 401 `invalid_token` |
| Write request (not GET/HEAD/OPTIONS) during a read-only impersonation | 403 `impersonation_read_only` |

The replay store must be shared by every PHP worker serving the API (Redis, database or memcached cache),
otherwise a captured proof could be replayed on another worker.

## DPoP from PHP clients

`GuillaumeTissier\ResourceGuard\Client\DpopProofFactory` creates proofs for server-to-server callers and tests:

```php
$dpop = DpopProofFactory::withNewKey();          // keep the key for the lifetime of the tokens
$header = $dpop->create('GET', 'https://api.example.com/items', $accessToken);
```

## Compatibility

The package follows [Semantic Versioning](https://semver.org/). The token claims it reads (`sub`, `aud`,
`scopes`, `cnf.jkt`, `act`, `imp`, `imp_mode`, `dom`, `acl`), the access expression syntax and the webhook format are a contract with
the [Auth Server](https://github.com/guillaumetissier/auth-server): a change to them is a major version.

## Development

```bash
composer install
composer test      # PHPUnit
composer cs        # checks the coding standard (PHP-CS-Fixer, Symfony rules), changes nothing
composer fixcs     # fixes it
```

## License

MIT, see [LICENSE](LICENSE).
