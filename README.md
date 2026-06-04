# LoopbackAuth — passwordless same-machine login for Kimai

A [Kimai](https://www.kimai.org/) plugin that auto-logs-in a user when the
request comes from the same machine (loopback). It modifies no Kimai core file,
so it survives upgrades.

The plugin itself holds **no credential logic**. It trusts a single signal —
the `REMOTE_USER` server variable — and delegates the actual trust decision to
your web server, which must be configured to set `REMOTE_USER` *only* for
loopback clients. The plugin is one half of the mechanism; the web server
configuration is the other, security-critical half.

> ### ⚠️ Security model — read before installing
>
> This plugin grants a session to whichever username your web server places in
> `REMOTE_USER`, **without a password**. Its safety rests entirely on the
> guarantee that your web server sets `REMOTE_USER` *exclusively* for loopback
> (`127.0.0.1` / `::1`) requests and strips any client-supplied value on every
> other path.
>
> If a reverse proxy, a misconfigured `fastcgi_param`, or an untrusted upstream
> can cause `REMOTE_USER` to be populated for a non-loopback request, this
> plugin becomes a full authentication bypass. Treat the web-server rule as part
> of the plugin: get it wrong and the plugin is wrong.
>
> Intended use is a single-operator, local-only Kimai instance (e.g. a
> workstation or a host reached only over an authenticated tunnel), where typing
> a password on every visit to your own machine is pure friction.

## Requirements

- Kimai **2.0** or newer (`extra.kimai.require: 20000`)
- PHP **8.1+**
- A web server that can set the `REMOTE_USER` FastCGI parameter conditionally
  (the examples below use nginx + PHP-FPM)

## How it works

Kimai is a Symfony application. Symfony's security layer forbids a plugin from
declaring firewall configuration in a second file, so this plugin reaches the
firewall at the dependency-injection container level instead:

1. **`Security/LoopbackAuthenticator`** is a self-validating
   [`AbstractAuthenticator`](https://symfony.com/doc/current/security/custom_authenticator.html).
   Its `supports()` returns `true` only when `REMOTE_USER` is a non-empty string
   *and* the current session is not already authenticated as that same user — so
   it does no redundant work on later requests, and it stands aside (returns
   `false`) for any request without `REMOTE_USER`, letting Kimai's normal
   `form_login` flow apply.
2. When it does fire, `authenticate()` returns a `SelfValidatingPassport` built
   from a `UserBadge` for the `REMOTE_USER` identifier, resolved against Kimai's
   internal user provider (`security.user.provider.concrete.kimai_internal`).
   There is no credential to check — the trust boundary is the web server — so
   the passport self-validates.
3. **`DependencyInjection/Compiler/RegisterLoopbackAuthenticatorPass`** appends
   the authenticator to the `secured_area` firewall's authenticator manager at
   compile time. This is the one Symfony-internal coupling in the plugin: it
   reads `security.authenticator.manager.secured_area` and adds a reference to
   the authenticator. **It fails safe** — if that service definition is not
   found (e.g. a future Symfony release renames it), the pass no-ops and the
   firewall simply lacks loopback auth; normal password login keeps working.

`onAuthenticationSuccess` and `onAuthenticationFailure` both return `null`:
success lets the request continue to its intended controller without a redirect,
and failure falls through to the other authenticators and the normal login entry
point.

## Installation

1. Copy the bundle into Kimai's plugin directory so the path is
   `var/plugins/LoopbackAuthBundle/`:

   ```bash
   cd /path/to/kimai
   git clone https://github.com/<owner>/<repo>.git var/plugins/LoopbackAuthBundle
   ```

   <!-- (Q: clone path assumes the repo root *is* the bundle. If you prefer the
   bundle nested one level down in the published repo, adjust the path.) -->

2. Clear and warm the Kimai cache so the compiler pass runs and the new
   authenticator is wired into the firewall:

   ```bash
   bin/console kimai:reload --env=prod
   # or, equivalently:
   bin/console cache:clear --env=prod
   ```

3. Confirm Kimai sees the plugin:

   ```bash
   bin/console kimai:bundles
   ```

   `LoopbackAuth` should appear in the list.

The user named in `REMOTE_USER` must already exist as a Kimai user — the plugin
authenticates an existing account, it does not create one.

## Web server configuration (the required other half)

The plugin is inert until your web server sets `REMOTE_USER`, and it is only
safe if your web server sets `REMOTE_USER` **only for loopback clients**. Below
is a representative nginx + PHP-FPM example. Adapt it to your deployment; do not
copy it blindly.

```nginx
# (Q: representative example — the project's actual servers/kimai.conf was not
# available when this README was written. Verify against your own deployment.)

# Default: never trust a client-supplied REMOTE_USER. Strip it.
fastcgi_param REMOTE_USER "";

# Only when the connection originates from the loopback interface do we assert
# an identity. $remote_addr is the real peer; it cannot be spoofed by an HTTP
# header. Map it to the Kimai username you want auto-logged-in.
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_pass unix:/run/php/php-fpm.sock;

    set $loopback_user "";
    if ($remote_addr = "127.0.0.1") { set $loopback_user "admin"; }
    if ($remote_addr = "::1")       { set $loopback_user "admin"; }
    fastcgi_param REMOTE_USER $loopback_user;
}
```

Key rules, regardless of web server:

- **Strip first, set second.** Establish `REMOTE_USER = ""` as the default and
  only populate it on the loopback branch, so no request path can inherit a
  stale or client-supplied value.
- **Key off the real peer address** (`$remote_addr` in nginx), never off a
  request header a client controls (`X-Forwarded-For`, `X-Remote-User`, etc.).
- **If Kimai sits behind a reverse proxy**, the loopback check must run on the
  edge that terminates the *real* client connection, not on an internal hop that
  always looks like loopback to the app server.

## Behaviour summary

| Request origin | `REMOTE_USER` | Result |
|---|---|---|
| Loopback, first request | set to a valid user | Auto-logged-in, no password |
| Loopback, already logged in as that user | set | Plugin stands aside; existing session used |
| Any non-loopback client | empty | Plugin stands aside; normal Kimai login form |
| Loopback, user does not exist in Kimai | set | Auth fails, falls through to normal login |

## Uninstall

```bash
rm -rf var/plugins/LoopbackAuthBundle
bin/console cache:clear --env=prod
```

Removing the bundle removes the authenticator from the firewall on the next
cache build. You should also remove the `REMOTE_USER` rule from your web-server
configuration.

## License

[MIT](LICENSE) © John Chandara
