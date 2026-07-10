<h1 align="center">palm</h1>

<p align="center">
  <strong>Fast subdomain live checking with neon 80s Miami energy.</strong>
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

**palm** is a fast and simple subdomain live checker with neon coast vibes: clean pipelines, quick signal, and just enough style to make recon feel less grey.

It reads subdomains from stdin or a `.txt` file, removes duplicates, normalizes messy tool output, and checks whether targets are live with DNS, HTTP, metadata, and takeover fingerprints.

## Why palm?

- Pipe-friendly: `subfinder -d example.com -silent | palm`
- File-friendly: `palm subs.txt`
- Fast enough for daily recon
- Simple output for chaining into other tools
- HTTP metadata: status, title, server, content length
- Takeover fingerprint checks
- Turkish and English help output
- Tiny Miami-mode easter egg hidden under the shade

## Install

```bash
go install github.com/kaaangumus/palm@latest
```

Make sure your Go bin directory is in `PATH`:

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
palm subs.txt
palm subs.txt -status
palm subs.txt -mc 200,301,302 -title -server
palm subs.txt -rt -location -follow-redirects=false
palm subs.txt -takeover
palm subs.txt -mode dns -status
palm subs.txt -mode both -json -o live.jsonl
```

Default mode is `http`, so palm prints live `https://` or `http://` URLs.

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

`-takeover` checks CNAME targets and known provider error fingerprints. Treat matches as takeover risk findings that should be manually verified before reporting.

## Responsible Use

Only scan domains and infrastructure you own or have permission to test. `palm` is built for authorized recon workflows.

## Flags

```text
-l, -list string   subdomain list file
-o string          output file
-mode string       dns, http, both (default "http")
-r string          resolver file for DNS lookups
-c int             concurrent workers (default 100)
-timeout int       timeout in seconds (default 5)
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
-q                 only print live hosts/URLs
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

With status:

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
{"host":"api.example.com","live":true,"dns":true,"ips":["104.20.23.154"],"url":"https://api.example.com","status_code":200}
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
