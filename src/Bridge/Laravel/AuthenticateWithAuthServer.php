<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Laravel;

use GuillaumeTissier\ResourceGuard\Guard\AuthenticationFailed;
use GuillaumeTissier\ResourceGuard\Guard\Principal;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware "auth.oauth".
 *
 *   Route::middleware('auth.oauth')->get(...);                         // any valid token
 *   Route::middleware('auth.oauth:orders.read,orders.write')->get(...); // every listed scope required
 *   Route::middleware('auth.oauth:no-impersonation')->post(...);       // never while impersonated
 *
 * Write requests during a read-only impersonation are refused by the ResourceGuard itself.
 *
 * The Principal is stored in the request attributes ("oauth_principal") and, when
 * "user_model" is configured, the matching Eloquent user becomes the authenticated user.
 */
final readonly class AuthenticateWithAuthServer
{
    public const PRINCIPAL_ATTRIBUTE = 'oauth_principal';
    public const NO_IMPERSONATION = 'no-impersonation';

    public function __construct(
        private ResourceGuard $guard,
        private AuthFactory $auth,
        private Config $config,
    ) {
    }

    public function handle(Request $request, \Closure $next, string ...$requiredScopes): Response
    {
        try {
            $principal = $this->guard->authenticate(
                $request->getMethod(),
                $request->url(),
                $request->headers->get('Authorization'),
                $request->headers->all('dpop'),
            );
        } catch (AuthenticationFailed $e) {
            return new JsonResponse($e->toArray(), $e->statusCode, [
                'WWW-Authenticate' => $e->wwwAuthenticate(),
                'Cache-Control' => 'no-store',
            ]);
        }

        if (\in_array(self::NO_IMPERSONATION, $requiredScopes, true)) {
            if ($principal->isImpersonated()) {
                return new JsonResponse(
                    ['error' => 'impersonation_forbidden', 'error_description' => 'This action is not available while impersonating a user'],
                    403,
                );
            }
            $requiredScopes = array_values(array_diff($requiredScopes, [self::NO_IMPERSONATION]));
        }

        foreach ($requiredScopes as $scope) {
            if (!$principal->hasScope($scope)) {
                return new JsonResponse(
                    ['error' => 'insufficient_scope', 'error_description' => \sprintf('Scope "%s" is required', $scope)],
                    403,
                    ['WWW-Authenticate' => \sprintf('DPoP error="insufficient_scope", scope="%s"', implode(' ', $requiredScopes))],
                );
            }
        }

        $request->attributes->set(self::PRINCIPAL_ATTRIBUTE, $principal);
        $this->bindUser($principal);

        return $next($request);
    }

    private function bindUser(Principal $principal): void
    {
        /** @var class-string<\Illuminate\Database\Eloquent\Model>|null $model */
        $model = $this->config->get('resource-guard.user_model');
        if (null === $model || '' === $model || !class_exists($model)) {
            return;
        }

        $user = $model::query()->find($principal->userId);
        if ($user instanceof \Illuminate\Contracts\Auth\Authenticatable) {
            $this->auth->guard()->setUser($user);
        }
    }
}
