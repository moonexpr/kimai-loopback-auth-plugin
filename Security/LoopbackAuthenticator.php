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
 * Defense in depth: the web server is *supposed* to set REMOTE_USER only for
 * trusted peers, but this authenticator does not rely on that alone. It also
 * verifies the real TCP peer address (REMOTE_ADDR) against a trusted CIDR
 * allowlist (default 127.0.0.1, ::1; override with the LOOPBACK_AUTH_TRUSTED_IPS
 * env var). A leaked or misconfigured REMOTE_USER is therefore not sufficient
 * to authenticate — the request must also originate from an allowlisted
 * network. The raw REMOTE_ADDR is used rather than Request::getClientIp()
 * because the latter honours X-Forwarded-* when trusted proxies are configured
 * and could be influenced by a client; REMOTE_ADDR is the actual peer.
 *
 * onAuthenticationSuccess/Failure both return null: success lets the request
 * continue to its intended controller (no redirect), and failure falls
 * through to the other authenticators / the form_login entry point.
 */

namespace KimaiPlugin\LoopbackAuthBundle\Security;

use Symfony\Component\HttpFoundation\IpUtils;
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
    /** @var list<string> Trusted peer allowlist (IPs/CIDRs) for REMOTE_ADDR. */
    private array $trustedIps;

    public function __construct(
        private readonly UserProviderInterface $userProvider,
        private readonly TokenStorageInterface $tokenStorage,
        string $trustedIps = '',
    ) {
        $parsed = array_values(array_filter(array_map('trim', explode(',', $trustedIps)), static fn (string $v): bool => $v !== ''));
        // Empty / unset config falls back to loopback only — the safe default.
        $this->trustedIps = $parsed !== [] ? $parsed : ['127.0.0.1', '::1'];
    }

    public function supports(Request $request): ?bool
    {
        $remoteUser = $request->server->get('REMOTE_USER');
        if (!\is_string($remoteUser) || $remoteUser === '') {
            return false;
        }

        // Defense in depth: independently confirm the real TCP peer is in the
        // trusted allowlist before honouring REMOTE_USER. See the class docblock
        // for why REMOTE_ADDR is used rather than Request::getClientIp().
        $remoteAddr = $request->server->get('REMOTE_ADDR');
        if (!\is_string($remoteAddr) || !IpUtils::checkIp($remoteAddr, $this->trustedIps)) {
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
