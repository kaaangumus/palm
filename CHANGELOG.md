# Changelog

## Unreleased

Fixes:

- `-render` now runs before the stdin/terminal check, so it works from an interactive shell and with `</dev/null`. `stdinIsTerminal` uses the platform `isTerminal` probe; `/dev/null` and `NUL` are character devices but not terminals.
- `-render` treats a closed pipe as a normal early exit.
- `-fw` is applied to JSON and XML reports too, not only text, JSONL and HTML.
- `-waf` uses GET when the body is needed, so body-based WAF signatures work without `-title`.
- `-takeover` keeps checking the CNAME chain when DNS resolution fails, so dangling CNAMEs on non-resolving hosts can be reported.
- Added `-include-dead`: JSONL output keeps non-live hosts too, so dangling CNAME records survive a line-oriented pipeline.

## 0.7.5

- `-tools` only lists tools whose pipelines were run end to end: subfinder,
  assetfinder, findomain, and httpx. `amass` (v5 needs API keys and returned
  nothing without them) and `chaos` (no Chaos key) were dropped rather than
  advertised as working.
- `dnsx` is no longer listed as a required step: `palm -mode dns` resolves hosts,
  so dnsx is optional.
- README intro and "Works Great With" trimmed to the same set.

## 0.7.4

- Input is stricter: a host must contain a dot and only valid DNS label
  characters. Before, banner text from tools that print headings on stdout
  ("Session Scope", "FQDN:") was taken for a hostname and each one cost a DNS
  lookup. Checked against real tool output: junk lines are dropped, `subs.txt`
  files and `httpx`/`dnsx` pipes still work.
- `-tools` notes corrected after running every example: `amass` v5 needs API keys
  in a config file and can finish with zero results without them, so the example
  says to verify its output before piping.

## 0.7.3

- `-tools` now lists examples that were actually run end to end, and says what to
  expect: `amass` passive is slow and can print nothing for a small domain,
  `chaos` needs `CHAOS_KEY`, and a missing `dnsx` is covered by `palm -mode dns`.
- Added the `httpx` and `dnsx` pipelines to `-tools`; both were working but
  undocumented.
- Examples now pass `-status`, so the output shows what the tool found instead of
  a bare URL.

## 0.7.2

Efficiency: a working HTTPS host now costs one request instead of two.

- HTTPS is tried first and the HTTP attempt only starts if HTTPS has not answered
  after 300 ms. Before, both schemes were fired in parallel for every host, so a
  scan always sent twice the requests it needed. Measured on a counter server:
  10 hosts went from 20 requests to 10.
- Under `-rate` this doubles throughput, because each host used to consume two
  tokens: 8 hosts at 4 req/s took 3.8 s, now 1.8 s.
- The fallback timer starts when the HTTPS request is actually on the wire, not
  when it is queued, so a rate-limited scan does not trigger both schemes.
- DNS is resolved once per host: the address from the DNS phase is reused by the
  HTTP dial instead of being looked up a second time. This also stops the two
  phases from disagreeing when DNS answers change mid-scan.
- Results are unchanged: same live set, same scheme, same status codes, and the
  scheme choice is still deterministic across runs.

## 0.7.1

- `-o` now picks the format from its extension when `-format` is not given, so
  `-o report.html` writes HTML instead of a text file named `.html`. An explicit
  `-format` still wins.
- Added `-render <file>`: converts a saved palm JSONL result into text, JSON,
  XML or HTML without scanning again.

## 0.7.0

Output clarity, WAF checks and export formats:

- `-print host|url|auto` picks what a text line starts with. `-print host` is the
  fix for "domain or URL?" ambiguity: every line is a bare hostname, and
  `final=`/`location=` lose their scheme too.
- `-waf` fingerprints the WAF or CDN in front of each host (Cloudflare, Akamai,
  Imperva, F5, Sucuri, Fastly, Merlin CDN, AWS WAF/CloudFront/ELB, Azure Front
  Door, Varnish, Wordfence, ModSecurity, Google Cloud Armor, Envoy) from headers,
  cookies and body of the probe palm already makes. No extra request.
- `-format text|jsonl|json|xml|html` adds single-array JSON, XML and a
  self-contained HTML report. Reports include dead hosts with their error;
  text and jsonl stay line-oriented for pipelines.
- Auto-save: with a terminal on stdout and no `-o`, results are also written to
  `palm-results/<name>-<timestamp>.<ext>`, so closing the window does not lose
  the scan. `-save=false` disables it, `-save-dir` moves it. Piped runs are
  unaffected.

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
