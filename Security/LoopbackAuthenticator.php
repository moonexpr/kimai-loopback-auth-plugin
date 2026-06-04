<?php

/*
 * Loopback authenticator.
 *
 * A self-validating pre-authentication authenticator: it trusts the
 * REMOTE_USER server variable, which the web server sets ONLY for loopback
 * clients (see the project's nginx servers/kimai.conf). There is no
 * credential to verify — the trust boundary is the web server — so the
 * passport is self-validating.
 *
 * This class is plugged into Kimai's existing secured_area firewall by
 * RegisterLoopbackAuthenticatorPass, so it runs inside the firewall and can
 * authenticate the very first request. It modifies no core file.
 *
 * supports() returns false when REMOTE_USER is empty (any non-loopback
 * client) — so the normal form_login flow applies — and also when the
 * current session is already authenticated as that same user, so it does no
 * redundant work on subsequent requests.
 *
 * onAuthenticationSuccess/Failure both return null: success lets the request
 * continue to its intended controller (no redirect), and failure falls
 * through to the other authenticators / the form_login entry point.
 */

namespace KimaiPlugin\LoopbackAuthBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class LoopbackAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly UserProviderInterface $userProvider,
        private readonly TokenStorageInterface $tokenStorage,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        $remoteUser = $request->server->get('REMOTE_USER');
        if (!\is_string($remoteUser) || $remoteUser === '') {
            return false;
        }

        // Already authenticated as this user (token restored from session)?
        // Skip — no need to re-authenticate on every request.
        $token = $this->tokenStorage->getToken();
        if ($token !== null && $token->getUserIdentifier() === $remoteUser) {
            return false;
        }

        return true;
    }

    public function authenticate(Request $request): Passport
    {
        $remoteUser = (string) $request->server->get('REMOTE_USER');

        return new SelfValidatingPassport(
            new UserBadge($remoteUser, fn (string $identifier) => $this->userProvider->loadUserByIdentifier($identifier)),
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }
}
