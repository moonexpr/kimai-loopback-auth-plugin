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

Kimai plugins are loaded from the `var/plugins/` directory; they are not
installed into `vendor/` like ordinary Composer libraries. Use the Git method
(the one Kimai documents); the Composer method is offered as a convenience for
installs that carry the `kimai/kimai2-composer` installer.

### 1. Install the plugin

**Git (recommended):** clone the bundle so its path is exactly
`var/plugins/LoopbackAuthBundle/` — the directory name must match the bundle
class for Kimai's autoloader to find it:

```bash
cd /path/to/kimai
git clone https://github.com/moonexpr/kimai-loopback-auth-plugin.git var/plugins/LoopbackAuthBundle
```

**Composer (alternative):** on a Kimai install whose root `composer.json`
includes the `kimai/kimai2-composer` installer (Kimai's `kimai-plugin` package
type routes the package to `var/plugins/` rather than `vendor/`):

```bash
composer require moonexpr/kimai-loopback-auth-plugin
```

### 2. Configure the web server

The plugin does nothing until your web server sets `REMOTE_USER` for loopback
clients. This is the security-critical half — see
[Web server configuration](#web-server-configuration-the-required-other-half)
below and the ready-made files in [`examples/nginx/`](examples/nginx/).

### 3. Rebuild the Kimai cache

So the compiler pass runs and the authenticator is wired into the firewall:

```bash
bin/console kimai:reload --env=prod
# or, equivalently:
bin/console cache:clear --env=prod
```

### 4. Confirm Kimai sees the plugin

```bash
bin/console kimai:bundles
```

`LoopbackAuth` should appear in the list.

The user named in `REMOTE_USER` must already exist as a Kimai user — the plugin
authenticates an existing account, it does not create one.

## Web server configuration (the required other half)

The plugin is inert until your web server sets `REMOTE_USER`, and it is only
safe if your web server sets `REMOTE_USER` **only for loopback clients**. Two
ready-made files in [`examples/nginx/`](examples/nginx/) do this for nginx +
PHP-FPM; adapt them to your deployment rather than copying blindly.

### Step 1 — define the loopback→user map

[`examples/nginx/loopback-auth-map.conf`](examples/nginx/loopback-auth-map.conf)
maps the **real peer address** to a username, defaulting to the empty string for
everyone else. Drop it into nginx's http context:

```bash
cp examples/nginx/loopback-auth-map.conf /etc/nginx/conf.d/kimai-loopback-auth.conf
# then edit it: set the username you want auto-logged-in for 127.0.0.1 / ::1
```

```nginx
map $remote_addr $kimai_loopback_user {
    default    "";
    127.0.0.1  "admin";
    ::1        "admin";
}
```

### Step 2 — forward it to PHP as `REMOTE_USER`

The Kimai vhost routes PHP through `location ~ ^/index\.php(/|$)`. One line
inside that block forwards the mapped value.
[`examples/nginx/enable-remote-user.patch`](examples/nginx/enable-remote-user.patch)
adds it for you, against Kimai's documented vhost:

```bash
patch -p1 --fuzz=3 /etc/nginx/sites-available/kimai.conf < examples/nginx/enable-remote-user.patch
```

If the hunk fails because your config differs, add the single line by hand
inside the `index.php` location:

```nginx
fastcgi_param REMOTE_USER $kimai_loopback_user;
```

Then validate and reload:

```bash
nginx -t && systemctl reload nginx
```

### Why it is built this way

- **Default empty, then map.** `$kimai_loopback_user` defaults to `""`, so no
  request path can inherit a stale or client-supplied value; only a loopback
  peer is given an identity.
- **Key off the real peer address** (`$remote_addr`), never off a client-
  controlled request header (`X-Forwarded-For`, `X-Remote-User`, etc.). A `map`
  on `$remote_addr` is preferred over `if` blocks — it cannot be tricked by a
  header and avoids nginx's [`if`-in-location pitfalls](https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/).
- **Behind a reverse proxy**, `$remote_addr` is the proxy, not the browser, so
  the map must run on the edge that terminates the *real* client connection —
  otherwise every proxied request looks like loopback.

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
