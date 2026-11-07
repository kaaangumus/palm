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

Check subdomain takeover fingerprints:

```bash
palm subs.txt -takeover
palm subs.txt -takeover -json
```

`-takeover` checks CNAME targets and known provider error fingerprints. `-json` records the resolved `cname` for every checked host, even when no fingerprint matches, so you can review dangling targets manually. Treat matches as takeover risk findings that should be manually verified before reporting.

## Responsible Use

Only scan domains and infrastructure you own or have permission to test. `palm` is built for authorized recon workflows.

## Flags

```text
-l, -list string   subdomain list file
-o string          output file
-mode string       dns, http, both (default "both")
-r string          resolver file for DNS lookups
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
-q                 only print live URLs, bare and pipe-friendly
-tools             show common tool pipelines
-check-update      check latest GitHub release
-update            update palm with go install
-version           show version
-h                 show help
```

Parameter names stay in English. If your Linux locale is Turkish, `palm -h` shows Turkish explanations automatically.

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

`-title` only reports a title when the final page is served by the same host. A login page from another host is not attributed to the subdomain; follow `final=` instead.

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
