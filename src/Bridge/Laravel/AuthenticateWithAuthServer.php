<?php

declare(strict_types=1);

namespace GuillaumeTissier\ResourceGuard\Bridge\Laravel;

use GuillaumeTissier\ResourceGuard\Guard\AuthenticationFailed;
use GuillaumeTissier\ResourceGuard\Guard\Principal;
use GuillaumeTissier\ResourceGuard\Guard\ResourceGuard;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
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
        private Settings $settings,
    ) {
    }

    public function handle(Request $request, \Closure $next, string ...$requiredScopes): Response
    {
        try {
            $principal = $this->guard->authenticate(
                $request->getMethod(),
                $request->url(),
                $request->headers->get('Authorization'),
                array_values(array_filter($request->headers->all('dpop'), \is_string(...))),
            );
        } catch (AuthenticationFailed $e) {
            return new JsonResponse($e->toArray(), $e->statusCode, $e->responseHeaders());
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

        $response = $next($request);
        if (!$response instanceof Response) {
            throw new \UnexpectedValueException(\sprintf('The next middleware returned %s instead of a response.', get_debug_type($response)));
        }

        return $response;
    }

    private function bindUser(Principal $principal): void
    {
        $model = $this->settings->userModel;
        if (null === $model || !is_a($model, \Illuminate\Database\Eloquent\Model::class, true)) {
            return;
        }

        $user = $model::query()->find($principal->userId);
        if ($user instanceof \Illuminate\Contracts\Auth\Authenticatable) {
            $this->auth->guard()->setUser($user);
        }
    }
}
