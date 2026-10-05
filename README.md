# Localzet SOCKS5

A PHP SOCKS5 TCP CONNECT proxy running on Localzet Server. This fork retains the original Walkor MIT notices; repository changes are covered by the project license.

[Русская документация](README.ru.md)

## Run

PHP 8.2+, the CLI process/network extensions required by Localzet Server, and Composer are required. Linux is the tested runtime.

```sh
composer install --no-dev
# Supply SOCKS5_USERNAME and SOCKS5_PASSWORD through your secret manager/environment.
php start.php start
php start.php stop
```

Configuration: `SOCKS5_BIND` (default `127.0.0.1`), `SOCKS5_PORT` (1080), `SOCKS5_USERNAME`, `SOCKS5_PASSWORD`. Missing credentials refuse startup. An explicit `SOCKS5_ALLOW_NO_AUTH=1` is supported only on a loopback bind. Never expose an anonymous proxy to a public network. Optional `SOCKS5_PID_FILE` and `SOCKS5_LOG_FILE` select service-managed runtime files.

SOCKS username/password authentication is plaintext on the wire, not encryption. Use a trusted local network or an authenticated encrypted tunnel; network binding is not a replacement for ingress controls. Logs do not dump authentication packets.

## Supported behavior

TCP CONNECT with IPv4 destinations and DNS names. Handshake data is buffered across TCP fragments; coalesced authentication/CONNECT messages and early relay payloads are retained. The buffer is bounded to 64 KiB and handshake establishment to 10 seconds. Connection failures return a SOCKS failure; successful replies use the actual outgoing socket bind address and port.

UDP ASSOCIATE is disabled in the shipped configuration. Its inherited implementation is experimental and has not been validated for per-client isolation; do not enable it for production. BIND and IPv6 destinations are not implemented and are rejected. DNS lookup currently blocks the worker; an asynchronous resolver, connection limits, rate limits and endpoint access policy remain deployment concerns.

This source revision changes defaults: the listener binds loopback, hardcoded `user/pass` is removed, anonymous authentication requires explicit opt-in, and UDP is no longer opened unconditionally. Review service configuration before upgrading. Workerman imports are replaced with the Localzet dependency already declared by the package.

## Validation

```sh
composer validate --no-check-publish
python3 tests/integration.py
```

The integration suite starts a temporary proxy and local echo server, then checks fragmented/coalesced handshakes, early TCP data, relay, wrong credentials and disabled UDP/anonymous access. CI does not deploy or publish a release. See `LICENSE` and `MIT-LICENSE.txt` for retained licensing.

## Attribution

Maintainer of Localzet contributions: **Ivan Zorin (localzet)** — <creator@localzet.com> · https://www.localzet.com. Copyright © 2026 Localzet Group. Original authorship and third-party licenses remain applicable. See [AUTHORS](.github/AUTHORS.md).
