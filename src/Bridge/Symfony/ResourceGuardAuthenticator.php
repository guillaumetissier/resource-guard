<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Symfony;

use GuillaumeTissier\ResourceGuard\Guard\AuthenticationFailed;
use GuillaumeTissier\ResourceGuard\Guard\Principal;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Symfony security authenticator. In security.yaml:
 *
 *   firewalls:
 *       api:
 *           pattern: ^/api
 *           stateless: true
 *           provider: app_user_provider        # loads users by the token "sub"
 *           custom_authenticators: [GuillaumeTissier\ResourceGuard\Bridge\Symfony\ResourceGuardAuthenticator]
 *           entry_point: GuillaumeTissier\ResourceGuard\Bridge\Symfony\ResourceGuardAuthenticator
 *
 * The Principal is available as the security token attribute "oauth_principal" and as a
 * request attribute of the same name.
 */
final class ResourceGuardAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public const PRINCIPAL_ATTRIBUTE = 'oauth_principal';

    private ?AuthenticationFailed $lastFailure = null;

    public function __construct(private readonly ResourceGuard $guard)
    {
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $principal = $this->guard->authenticate(
                $request->getMethod(),
                $request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo(),
                $request->headers->get('Authorization'),
                $request->headers->all('dpop'),
            );
        } catch (AuthenticationFailed $e) {
            $this->lastFailure = $e;

            throw new CustomUserMessageAuthenticationException($e->getMessage(), [], 0, $e);
        }

        $request->attributes->set(self::PRINCIPAL_ATTRIBUTE, $principal);

        $passport = new SelfValidatingPassport(new UserBadge($principal->userId));
        $passport->setAttribute(self::PRINCIPAL_ATTRIBUTE, $principal);

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $token = parent::createToken($passport, $firewallName);
        $token->setAttribute(self::PRINCIPAL_ATTRIBUTE, $passport->getAttribute(self::PRINCIPAL_ATTRIBUTE));

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $failure = $this->lastFailure
            ?? AuthenticationFailed::invalidToken('Unknown user', true);
        $this->lastFailure = null;

        return $this->toResponse($failure);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return $this->toResponse(AuthenticationFailed::missingCredentials(true));
    }

    public static function principal(?TokenInterface $token): ?Principal
    {
        $principal = $token?->hasAttribute(self::PRINCIPAL_ATTRIBUTE) ? $token->getAttribute(self::PRINCIPAL_ATTRIBUTE) : null;

        return $principal instanceof Principal ? $principal : null;
    }

    private function toResponse(AuthenticationFailed $failure): Response
    {
        return new JsonResponse($failure->toArray(), $failure->statusCode, [
            'WWW-Authenticate' => $failure->wwwAuthenticate(),
            'Cache-Control' => 'no-store',
        ]);
    }
}
