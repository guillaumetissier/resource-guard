# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-05

### Added
- Facets in access expressions: `vehicle.pricing:w` grants a part of a resource. The most specific rule wins
  (facet, then its type, then `*`), a facet right of level read or more also grants read on its type, and
  facets take `-`, `r` or `w` only. `isWithin()` takes facets into account.
- `Principal::deniedFacets()`: the facets of a type on which the caller lacks a level, before a partial update.
- `AccessExpression::parentType()` and `AccessExpression::FACET_SEPARATOR`.

### Changed
- A dot in a type name now separates a type from its facet: resource types can no longer contain dots
  (`a.b.c` and `*.x` are refused, `a.b` is the facet `b` of `a`).

## [0.1.0] - 2026-10-22

First public version.

- `ResourceGuard`: offline validation of RS256 JWT access tokens through a JWKS endpoint (expiry, audience/client allow-list, scopes).
- DPoP proof validation (RFC 9449): signature, `htm`, `htu`, `iat` window, `ath`, `cnf.jkt` binding, replay protection (PSR-16 or in-memory store).
- Impersonation details (`act` claim) on the `Principal`; write requests refused during read-only impersonations.
- Webhook signature verification (HMAC-SHA256) and event value object.
- Adapters: Laravel (service provider, `auth.oauth` middleware, webhook route), Symfony (security authenticator, webhook controller), PSR-15 middleware.
- `DpopProofFactory` for PHP clients and tests.
- Access control: `AccessLevel` enum, `AccessExpression` (`*:w tire:r user:w:own @access:w`), `AccessControlList`
  built from the `dom` / `acl` claims, `DomainPath`; `Principal::can()`, `accessLevel()`, `domain()`, `acl()`.
- `WebhookEvent::USER_ACCESS_CHANGED`.
- `AuthenticationFailed::responseHeaders()`; the adapters send `WWW-Authenticate` on 401 only (PHP's `header()`
  turned a 403 carrying it into a 401).
- `HttpJwksProvider`: the forced-refresh rate limit is shared through the cache, so it holds under PHP-FPM.
- Functional test tool (`tools/rg-cli.php check`): stand-in issuer, demo API, 40 end-to-end scenarios.
- PHPStan at level max. Laravel configuration read through a typed `Settings` object: environment strings
  (`"false"`, `"60"`, `"a,b"`) are normalized, `AUTH_SERVER_ALLOWED_CLIENTS` accepts a comma-separated string or an
  array; null entries in `DPoP` headers are ignored.
- RS256 tokens verified through OpenSSL with a byte-level JWK to PEM conversion, cached per key: no
  big-integer arithmetic, so verification costs well under a millisecond even without ext-gmp or ext-bcmath.

[Unreleased]: https://github.com/guillaumetissier/resource-guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/guillaumetissier/resource-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/guillaumetissier/resource-guard/releases/tag/v0.1.0
