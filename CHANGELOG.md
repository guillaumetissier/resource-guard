# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - unreleased

First public version.

- `ResourceGuard`: offline validation of RS256 JWT access tokens through a JWKS endpoint (expiry, audience/client allow-list, scopes).
- DPoP proof validation (RFC 9449): signature, `htm`, `htu`, `iat` window, `ath`, `cnf.jkt` binding, replay protection (PSR-16 or in-memory store).
- Impersonation details (`act` claim) on the `Principal`; write requests refused during read-only impersonations.
- Webhook signature verification (HMAC-SHA256) and event value object.
- Adapters: Laravel (service provider, `auth.oauth` middleware, webhook route), Symfony (security authenticator, webhook controller), PSR-15 middleware.
- `DpopProofFactory` for PHP clients and tests.
