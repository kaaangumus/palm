<h1 align="center">palm</h1>

<p align="center">
  <strong>Bug bounty subdomain recon pre-filter for live and takeover checks.</strong>
</p>

<p align="center">
  <img src="assets/palm-banner.svg" width="820" alt="palm neon 80s Miami subdomain live checker banner">
</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white">
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/kaaangumus/palm/ci.yml?branch=main&style=for-the-badge&label=CI">
  <img alt="License" src="https://img.shields.io/github/license/kaaangumus/palm?style=for-the-badge">
  <img alt="Recon" src="https://img.shields.io/badge/recon-pipeline-ff4fd8?style=for-the-badge">
  <img alt="Mode" src="https://img.shields.io/badge/mode-http%20%7C%20dns%20%7C%20both-00ffc6?style=for-the-badge">
</p>

<p align="center">
  <code>subfinder -d example.com -silent | palm -status -title -server</code>
</p>

**palm** is a bug bounty focused subdomain recon pre-filter. It sits after tools like `subfinder`, `amass`, `assetfinder`, `findomain`, or `chaos` and turns noisy discovery output into clean, live, actionable targets.

It reads subdomains from stdin or a `.txt` file, removes duplicates, normalizes messy tool output, checks DNS/HTTP liveness, adds lightweight context, and highlights possible subdomain takeover risks.

## Why palm?

- Pipe-friendly: `subfinder -d example.com -silent | palm`
- File-friendly: `palm subs.txt`
- Built for post-discovery bug bounty triage
- Clean live target output for notes, reports, or the next tool
- Lightweight context: status, title, server, content length, response time
- Takeover fingerprint checks for quick risk prioritization
- Turkish and English help output
- Tiny Miami-mode easter egg hidden under the shade

## What palm is

`palm` is a focused triage step between subdomain discovery and deeper testing:

```text
subdomain discovery -> palm -> manual review / deeper tooling
```

Use it when you want to quickly answer:

- Which discovered subdomains resolve?
- Which ones are HTTP/HTTPS live?
- Which live targets look worth opening first?
- Are there obvious takeover-risk fingerprints?

## What palm is not

`palm` is not an `httpx` clone or a full web fingerprinting engine.

It intentionally does not try to be a screenshot tool, technology detector, WAF/CDN analyzer, favicon hasher, TLS deep inspector, path brute forcer, or headless browser. Those jobs belong to specialized tools. `palm` stays small so the bug bounty workflow stays fast.

## Install

### Windows (one command)

PowerShell (no admin rights needed):

```powershell
irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex
```

The installer downloads `palm_windows_<arch>.exe` from the latest release, installs it to
`%LOCALAPPDATA%\Programs\palm`, and adds that folder to your user `PATH`. Open a new
terminal and run:

```powershell
palm -version
```

Custom install folder or a pinned version (the script reads environment variables, because
`irm | iex` cannot take PowerShell parameters):

```powershell
# custom folder
$env:PALM_INSTALL_DIR = "$HOME\bin"
irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex

# pinned version
$env:PALM_VERSION = "v0.3.0"
irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex
```

If script execution is blocked in your session, run it with a one-off policy override
instead of changing the machine setting:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex"
```

To uninstall, delete `%LOCALAPPDATA%\Programs\palm` and remove that entry from your user `PATH`.

### Linux / macOS

Recommended install:

```bash
curl -fsSL https://raw.githubusercontent.com/kaaangumus/palm/main/install.sh | sh
```

If you do not have `curl`:

```bash
wget -qO- https://raw.githubusercontent.com/kaaangumus/palm/main/install.sh | sh
```

The installer downloads the latest release binary and places it in `/usr/local/bin`, so you can run:

```bash
palm -version
```

Release downloads are verified against the release's `checksums.txt` (SHA-256) by both installers when that file is available; older releases without checksums are installed with a warning.

Install without sudo:

```bash
curl -fsSL https://raw.githubusercontent.com/kaaangumus/palm/main/install.sh | PALM_INSTALL_DIR="$HOME/.local/bin" sh
```

### Go

```bash
go install github.com/kaaangumus/palm@latest
```

If you install with Go, make sure your Go bin directory is in `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Build from source:

```bash
git clone https://github.com/kaaangumus/palm.git
cd palm
go build -o palm .
```

Build a Linux binary from another system:

```bash
GOOS=linux GOARCH=amd64 go build -o palm .
```

Build a Windows binary from another system:

```bash
GOOS=windows GOARCH=amd64 go build -o palm.exe .
```

Release binaries are generated automatically when a `v*` tag is pushed.

Update later:

```bash
palm -update
```

`-update` replaces the running binary with the latest release: it downloads the asset for your platform, verifies it against `checksums.txt`, confirms the downloaded binary reports the new version, then swaps it in. If the install directory is not writable it says so (`sudo palm -update` fixes that on Linux). When the release has no asset for your platform, it falls back to `go install`, and finally to printing the installer command.

Check whether a newer release exists:

```bash
palm -check-update
```

## Quick Start

```bash
subfinder -d example.com -silent | palm -status -title -server -rt
subfinder -d example.com -silent | palm -takeover -status
subfinder -d example.com -silent | palm -mode dns -status -o resolved.txt
subfinder -d example.com -silent | palm -json -status -title -server -o live.jsonl
```

Default mode is `both`, so palm resolves each host with DNS first and then prints live `https://` or `http://` URLs for hosts that pass both checks.

## Bug Bounty Workflow

Collect subdomains:

```bash
subfinder -d example.com -silent | tee subs.txt
```

Resolve and clean:

```bash
palm subs.txt -mode dns -status -o resolved.txt
```

Find live web targets:

```bash
palm subs.txt -status -title -server -rt -o live.txt
```

Check takeover-risk fingerprints:

```bash
palm subs.txt -takeover -json -o takeover-check.jsonl
```

Then manually review the interesting targets. Takeover matches are risk hints, not final proof.

## Works Great With

Five common subdomain discovery tools:

```bash
subfinder -d example.com -silent | palm
assetfinder --subs-only example.com | palm
amass enum -passive -d example.com | palm
findomain -t example.com -q | palm
chaos -d example.com -silent | palm
```

Resolver output also works:

```bash
dnsx -l subs.txt -silent | palm -mode http -status
```

Show these examples from the CLI:

```bash
palm -tools
```

## Full Pipeline Script

`recon.sh` chains palm with the usual recon tools, so one command goes
from a domain to live endpoints, parameters and WAF notes:

```bash
chmod +x recon.sh
./recon.sh -d example.com
./recon.sh -d example.com --rate 5 -c 50
./recon.sh -d example.com -i subs.txt --no-history
./recon.sh -d example.com -o recon/example --with-nuclei
```

Stages: passive enumeration (subfinder, assetfinder, findomain, amass) ->
resolve with wildcard filtering through palm -> HTTP probe with status, title,
server, TLS and takeover -> parameter collection with katana, gau and
waybackurls -> WAF fingerprinting with wafw00f -> optional nuclei scan.

Everything lands in one directory: `subs.txt`, `resolved.txt`, `live.txt`,
`live.jsonl`, `params.txt`, `params.uniq`, `waf.txt`, `summary.txt`, plus
`run.log`. Stages are resumable, so a second run only fills in what is missing;
`--force` reruns them all.

Every external tool is optional and every call has a timeout with stdin closed,
so a missing or half-broken tool (or one that asks for a password) is skipped
with a notice instead of stalling the run.

## Modes

```text
http   Try HTTPS first, then HTTP. Print live URLs.
dns    Resolve hosts. Print hosts that resolve.
both   Resolve first, then HTTP check. Print targets that pass both.
```

## Useful Filters

Match only selected HTTP status codes:

```bash
palm subs.txt -mc 200,301,302,403
```

Filter noisy status codes:

```bash
palm subs.txt -fc 404,500
```

Add lightweight HTTP metadata:

```bash
palm subs.txt -status -title -server -cl
```

Show response timing and redirect targets:

```bash
palm subs.txt -status -rt -location -follow-redirects=false
```

Send custom methods or headers:

```bash
palm subs.txt -method GET -H "User-Agent: palm-recon" -H "X-Recon: palm"
```

Use your own DNS resolvers:

```bash
palm subs.txt -mode dns -r resolvers.txt
```

`-r` applies to both DNS queries and HTTP dials, including in `-mode http`; the resolver file is no longer limited to the DNS phase.

Check subdomain takeover fingerprints:

```bash
palm subs.txt -takeover
palm subs.txt -takeover -json
```

`-takeover` covers 37 services from the community list at [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), keeping the entries still reported as vulnerable plus the edge cases that keep appearing in reports. Services marked "not vulnerable" there are deliberately left out because they only create false positives.

A host is reported as a takeover in two ways:

- **Dangling provider target**: the subdomain CNAMEs to a provider hostname that no longer resolves (a deleted S3 bucket, a removed Azure app, an expired Elastic Beanstalk environment). Anyone who can claim that name at the provider takes the host over. This is the strongest signal and needs no page fetch.
- **Provider error page**: the CNAME points at a known provider and the response body is that provider's "this name is not taken" page.

A dangling target at an unknown provider is reported separately as `dangling`: the CNAME target does not resolve, but the provider cannot hand out names, so it is a record to review rather than a takeover. Text output adds `dangling` and JSON sets `"dangling": true`. `-json` records the resolved `cname` for every checked host even when nothing matches. Treat every match as a risk finding that should be verified manually before reporting.

Takeover mode performs one HTTP GET per live host, because some providers can only be recognised by their error page. Hosts whose HTTP phase already failed skip that request.

Inspect TLS certificates:

```bash
palm subs.txt -tls -status
palm subs.txt -tls -json -o certs.jsonl
```

`-tls` reports the leaf certificate issuer, expiry, and whether the certificate covers the host it was presented for. The request itself still accepts self-signed and expired certificates, so a host with a broken certificate is still reported as live; `tls_mismatch` marks a certificate that does not cover its hostname.

Handle wildcard DNS:

```bash
palm subs.txt -wildcard -status
palm subs.txt -wildcard -fw
```

A wildcard DNS record makes every invented subdomain resolve, which pollutes recon results. `-wildcard` resolves one random name per parent domain and marks hosts that resolve to the same addresses (`wildcard` in text, `"wildcard":true` in JSON). `-fw` drops them.

Shared hosting suffixes such as `github.io`, `appspot.com`, `herokuapp.com`, `netlify.app`, `vercel.app`, and `s3.amazonaws.com` are skipped: probing them would flag every real project site. Detection compares addresses only, so a host behind a shared CDN can still be marked even when it is real; verify before discarding. Both flags require `-mode dns` or `both`; `-mode http` exits with an error because there is no DNS resolution to compare against.

## Output and Speed Control

Pick what each line starts with:

```bash
palm subs.txt -print host        # api.example.com          (bare hostname)
palm subs.txt -print url         # https://api.example.com  (full URL)
palm subs.txt -print auto        # default: URL for http modes, host for dns
```

`-print host` is the fix for "is this a domain or a URL?" confusion: with it,
every text line starts with a hostname, and `final=` / `location=` values lose
their scheme too. `-no-scheme` still exists and keeps the path
(`api.example.com/login`), which is different from `-print host`.

Export results in the shape you need:

```bash
palm subs.txt -format text        # one line per live host (default)
palm subs.txt -format jsonl       # JSON lines, one object per host
palm subs.txt -format json        # a single JSON array
palm subs.txt -format xml         # <results><result>...</result></results>
palm subs.txt -format html -o report.html
```

`json`, `xml` and `html` are reports: they include dead hosts with their error so
the file explains what was checked. `text` and `jsonl` stay one-record-per-line
for pipelines. The HTML report is self-contained, marks takeover and dangling
rows, and opens straight in a browser.

The output extension picks the format when `-format` is not given, so
`-o report.html` really writes HTML:

```bash
palm subs.txt -o report.html        # HTML
palm subs.txt -o results.xml        # XML
palm subs.txt -o data.json          # JSON array
palm subs.txt -o report.html -format text   # explicit -format still wins
```

Convert a saved scan without scanning again:

```bash
palm -render live.jsonl -format html -o report.html
palm -render live.jsonl -format xml | xmllint --format -
palm -render live.jsonl -status     # back to text
```

This is useful when a scan is already done, or when the pipeline saved
`live.jsonl` and you want a report later.

Detect what sits in front of the host:

```bash
palm subs.txt -status -waf
```

`-waf` fingerprints Cloudflare, Akamai, Imperva, F5, Sucuri, Fastly, Merlin CDN,
AWS (WAF, CloudFront, ELB), Azure Front Door, Varnish, Wordfence, ModSecurity,
Google Cloud Armor and Envoy from the response palm already fetched. No extra
request.

Auto-save while looking at the screen:

```bash
palm subs.txt -status -title   # writes palm-results/<name>-<timestamp>.txt too
palm subs.txt -save=false       # turn it off
```

When stdout is a terminal and no `-o` is given, palm writes a timestamped copy
next to the output so closing the window does not lose the scan. Piped runs are
never touched. `-save-dir` chooses where the file goes. The extension follows
`-format`, so `-format html` auto-saves an `.html` report.

Stream results as they arrive instead of waiting for the whole scan:

```bash
palm subs.txt -no-sort -q
```

Drop the URL scheme when you want bare hosts:

```bash
palm subs.txt -q -no-scheme        # api.example.com
palm subs.txt -status -no-scheme   # api.example.com [200 | ip=...]
```

`-no-scheme` affects text output only; JSON keeps full URLs so parsers still see the scheme.

The default still sorts by host name. `-no-sort` writes each result the moment it finishes, so a long scan starts printing immediately and memory stays flat. Filters, `-q`, `-json`, and the atomic output file behave the same either way.

Show progress on stderr while scanning:

```bash
palm subs.txt -progress -o live.txt
```

`-progress` never writes to stdout, so pipelines and `-q`/`-json` output are unaffected.

Stay polite to the target with a request rate cap:

```bash
palm subs.txt -rate 5          # at most 5 HTTP requests per second
palm subs.txt -delay 200ms     # at least 200ms between requests
```

The limiter covers every HTTP request, including the HTTPS and HTTP attempts and takeover body fetches. DNS lookups are not rate limited.

Pick the help language explicitly:

```bash
palm -lang tr -h
palm -lang en -h
```

## Performance

Each host is probed once, but palm does not wait for HTTPS before trying HTTP:

- Both `https://` and `http://` are probed in parallel under one `-timeout` budget, so a host that blackholes port 443 still gets its HTTP chance, and a host that only answers over HTTP is found in one timeout instead of two.
- HTTPS is always preferred: when both answer, the HTTPS result wins. The choice never depends on which scheme answered first, so the same host reports the same scheme on every run.
- HTTP/2 stays enabled even though certificate verification is skipped, so h2 sites only need one connection.
- A failed `HEAD` (a server that hangs up or resets) is retried once with `GET`, which recovers sites that reject HEAD.
- `-title` stops reading as soon as `</title>` is seen instead of downloading the whole capped body.

On a 900-host corpus, the median gain is small for hosts that answer quickly and large for slow or mixed hosts (roughly 30% faster at `-c 300`).

## Responsible Use

Only scan domains and infrastructure you own or have permission to test. `palm` is built for authorized recon workflows.

## Flags

```text
-l, -list string   subdomain list file
-o string          output file
-mode string       dns, http, both (default "both")
-r string          resolver file for DNS lookups and HTTP dials
-c int             concurrent workers (default 100)
-timeout int       timeout in seconds per phase (DNS, HTTP) (default 5)
-mc string         match HTTP status codes, comma-separated
-fc string         filter HTTP status codes, comma-separated
-json              write JSON lines
-status            include HTTP status or DNS IPs in text output
-title             include page title
-server            include server header
-cl                include content length
-rt                include response time
-location          include redirect Location header
-follow-redirects  follow HTTP redirects (default true)
-method string     HTTP method
-H string          custom HTTP header, repeatable
-takeover          check subdomain takeover fingerprints
-tls               include TLS certificate summary
-wildcard          detect wildcard DNS and mark matching hosts
-fw                drop hosts that match a wildcard DNS record
-q                 only print live URLs, bare and pipe-friendly
-print string      leading text value: host, url, auto (default "auto")
-format string     output format: text, jsonl, json, xml, html (default "text")
-render string     convert an existing JSONL file to -format (no scan)
-waf               detect the WAF or CDN in front of each host
-save              write a timestamped copy when output goes to a terminal (default true)
-save-dir string   directory for -save (default "palm-results")
-no-sort           print in completion order instead of host order
-no-scheme         omit the http:// or https:// prefix in text output
-progress          print progress to stderr
-rate float        max HTTP requests per second (0 = unlimited)
-delay duration    minimum delay between HTTP requests, e.g. 200ms
-lang string       help language: en, tr (default: auto)
-tools             show common tool pipelines
-check-update      check latest GitHub release
-update            self-update to the latest release
-version           show version
-h, -help          show help
```

Parameter names stay in English. If your Linux locale is Turkish, `palm -h` shows Turkish explanations automatically. Override it with `-lang en` or `-lang tr`.

Example:

```bash
LANG=tr_TR.UTF-8 palm -h
```

## Output Examples

Plain live HTTP output:

```text
https://api.example.com
https://app.example.com
http://dev.example.com
```

With status (default `both` mode also shows resolved IPs):

```text
https://api.example.com [200 | ip=104.20.23.154]
https://app.example.com [302 | ip=172.66.147.243]
```

With a cross-host redirect (default `-follow-redirects`), the probed subdomain stays first and the final URL is added as `final=`:

```text
https://0b295af.sites.google.com [200 | final=https://accounts.google.com/ServiceLogin?...]
```

A redirect that stays on the same host is not shown, so `https://host/` → `https://host/Security/Login` prints as a plain `https://host [200]` line. Use `-location -follow-redirects=false` when you want to see that path-level hop.

`-title` only reports a title when the final page is served by the same site: the same hostname, or a `www.` ↔ apex redirect. A login page from another host is not attributed to the subdomain; follow `final=` instead.

`-timeout` is a budget per phase: the DNS lookup gets one budget, and the HTTP phase shares one budget across the HTTPS and HTTP attempts, so a slow host cannot cost `2 x -timeout`.

With status in `http` mode:

```text
https://api.example.com [200]
https://app.example.com [302]
```

DNS mode with IPs:

```text
api.example.com 104.20.23.154,172.66.147.243
```

JSON lines:

```json
{"host":"www.github.com","live":true,"dns":true,"ips":["140.82.121.3"],"url":"https://github.com/","probed_url":"https://www.github.com","status_code":200}
```

## Exit Codes

```text
0    scan finished, including an empty result
1    configuration, input, or output error
130  interrupted with Ctrl+C; partial results are kept
```

## Easter Egg

Somewhere under the palm tree:

```bash
palm -miami
```

`Kaan Gümüş`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
