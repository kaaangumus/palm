# Changelog

## 0.5.0

Performance:

- HTTP/2 is now enabled; a custom `TLSClientConfig` had silently downgraded every request to HTTP/1.1.
- HTTPS and HTTP are probed in parallel under one `-timeout` budget, so a host that blackholes 443 no longer loses its HTTP chance and no host costs `2 x -timeout`. HTTPS still wins when both answer.
- DNS resolvers are built once per pool instead of for every lookup.
- A failed `HEAD` (hang-up, reset, empty reply) is retried with `GET`, which finds hosts that reject HEAD.
- `-title` streams the body and stops at `</title>` instead of reading up to 512 KB per host.

New:

- `-tls` reports the certificate issuer, expiry, and hostname mismatch.
- `-wildcard` detects wildcard DNS and marks matching hosts; `-fw` drops them.
- JSON gains `wildcard`, `tls_issuer`, `tls_expires`, `tls_days_left`, and `tls_mismatch`.

## 0.4.0

- Changed the default `-mode` from `http` to `both`, so hosts are DNS-resolved before the HTTP probe.
- `-timeout` is now a budget per phase: the HTTPS and HTTP attempts share one budget, so a hanging host no longer costs `2 x -timeout`.
- `-title` no longer reports the title of a different host reached through a cross-host redirect. A `www.` ↔ apex redirect still counts as the same site and keeps its title.
- `-json` now records the resolved `cname` for every `-takeover` host, even when no fingerprint matches.
- HTTP text output now starts with the probed subdomain URL and adds `final=` only when a redirect ends on a different URL. Before, a redirect to another host (for example Google login pages) replaced the subdomain entirely.
- Added `probed_url` to JSON output; `url` still holds the final URL after redirects.
- `-q` now prints bare, pipe-friendly URLs only, without metadata brackets.
- `-status` now shows resolved IPs (`ip=...`) on HTTP output in `both` mode.
- DNS failures in `both` mode are reported in `error` instead of being silent.
- An unusable resolver file now fails with an error and exit code 1 instead of printing nothing.
- A missing input file now hints that a single host is read from stdin (`echo host | palm`).
- Bracketed IPv6 input such as `[::1]:8080` is no longer parsed as `::1]:8080`.
- Silent `http.Transport` "Unsolicited response" log lines are no longer written to stderr.

## 0.3.0

- Added self-update support with `-update`.
- Added release checks with `-check-update`.

## 0.2.0

- Added response time output with `-rt`.
- Added redirect `Location` output with `-location`.
- Added redirect control with `-follow-redirects`.
- Added custom HTTP method support with `-method`.
- Added repeatable custom HTTP headers with `-H`.
- Refreshed Turkish help output to avoid terminal encoding issues.

## 0.1.0

- Initial `palm` CLI.
- Stdin and `.txt` input support.
- HTTP, DNS, and combined check modes.
- Status filters with `-mc` and `-fc`.
- HTTP metadata with `-title`, `-server`, and `-cl`.
- Custom resolver support with `-r`.
- Subdomain takeover fingerprint checks with `-takeover`.
- Turkish and English help output.
