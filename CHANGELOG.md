# Changelog

## 0.6.4

Takeover detection was too narrow: 10 fingerprints, and the list only ran when the CNAME already matched one of them, so a whole class of findings was invisible.

- Fingerprints now cover 37 services from the community list at can-i-take-over-xyz, keeping the entries still reported as vulnerable plus the edge cases that keep appearing in reports. Services marked "not vulnerable" were dropped because they only produced false positives (Zendesk closed help centers, for example).
- Added dangling-CNAME detection: when a subdomain points at a provider hostname that no longer resolves, it is reported as a takeover. Deleted buckets, removed Azure apps, and expired Elastic Beanstalk environments are all found this way, and it needs no page fetch.
- Fixed the gate that made provider page fingerprints unreachable: services with no dedicated CNAME (Pantheon, Canny, DigitalOcean, GetResponse, Pingdom, Readthedocs, Short.io, Campaign Monitor, SmartJobBoard) are now checked by their error page instead of never being checked at all.
- A CNAME target that does not resolve at an unlisted provider is reported as `dangling` rather than `takeover`, so dangling records can be reviewed without claiming a vulnerability.
- Takeover mode skips the body fetch when the HTTP phase already failed, which makes it faster than before on dead hosts (about 16 s vs 19 s on a 900-host corpus).

## 0.6.3

- The scheme in the output is deterministic again. HTTPS is used whenever it produced a usable response, instead of only when it answered within 250 ms of HTTP. Hosts whose TLS handshake was slower could flip between `https://` and `http://` from run to run (6 of 217 live hosts on a test corpus did). No speed change on the same corpus, and 17 more hosts are now correctly reported over HTTPS.

## 0.6.2

- `final=` now appears only when a redirect changes the host. A same-host redirect such as `https://host/` to `https://host/Security/Login` prints as a plain `https://host [200]` line, which keeps triage output short. `-location -follow-redirects=false` still shows the raw hop.

## 0.6.1

- Added `-no-scheme`: text output (`-q` included, and `final=`) drops the `http://` / `https://` prefix. JSON keeps full URLs.
- Fixed the 0.6.0 changelog heading: the entries below belonged to 0.6.0.

## 0.6.0

Self-update:

- `-update` now replaces the running binary in place: it downloads the release asset for the current platform, verifies it against the published `checksums.txt`, checks the new binary reports the expected version, and swaps it in atomically. `go install` remains a fallback, and the installer hint is printed when that also fails.

Performance and control:

- `-no-sort` streams results in completion order instead of buffering the whole scan; the default output stays sorted by host.
- `-progress` prints a periodic `checked / live / failed` line to stderr, never to stdout.
- `-rate` and `-delay` cap HTTP request speed with an internal limiter (no new dependency). DNS lookups are not limited.
- `readTitle` scans incrementally instead of re-scanning the whole buffer per chunk; a 256 KB page now costs one linear pass (benchmark included).
- `parentDomain` no longer probes shared hosting suffixes (`github.io`, `appspot.com`, `herokuapp.com`, `netlify.app`, `vercel.app`, `s3.amazonaws.com`, and others), which used to mark real project sites as wildcards.

CLI:

- `-lang en|tr` selects the help language explicitly; auto detection still applies when omitted.
- `-help` is now listed in the usage text.

Fixes:

- `-wildcard` and `-fw` now fail with a clear error in `-mode http` instead of silently doing nothing; wildcard detection requires `-mode dns` or `both`.
- `-r` now drives HTTP connections too, so a custom resolver file applies to the whole host check, not only to the DNS phase.
- `-title` no longer shifts byte offsets when Unicode characters appear before the `<title>` tag.
- `-update` on a release-binary install prints the installer command instead of failing on a missing Go toolchain.
- `-o` writes through a temporary file and replaces the destination only after the scan completes, so an interrupted run cannot truncate an existing result file. Ctrl+C keeps partial results and exits with code 130.
- Write errors are reported; a closed pipe (`palm | head`) is treated as a normal early exit.
- Takeover CNAME matching now respects DNS label boundaries, and generic provider names were removed from body fingerprints to reduce false positives.

Tooling:

- Release builds inject the tag into `main.version` and verify it before publishing.
- Releases publish `checksums.txt`; both installers verify SHA-256 when the file is available.
- CI runs `go test -race`, staticcheck, and govulncheck, plus a Windows test job; releases are gated on tests.

## 0.5.0

Performance:

- HTTP/2 is now enabled; a custom `TLSClientConfig` had silently downgraded every request to HTTP/1.1.
- HTTPS and HTTP are probed in parallel under one `-timeout` budget, so a host that blackholes 443 no longer loses its HTTP chance and no host costs `2 x -timeout`. HTTPS still wins when both answer.
- DNS resolvers are built once per pool instead of for every lookup.
- A failed `HEAD` (hang-up, reset, empty reply) is retried with `GET`, which finds hosts that reject HEAD.
- `-title` streams the body and stops at `</title>` instead of reading the whole capped body per host.

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
