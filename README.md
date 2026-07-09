# palm

![South Beach palms](https://commons.wikimedia.org/wiki/Special:Redirect/file/South_Beach_palms_%28Unsplash%29.jpg)

Photo: [South Beach palms](https://commons.wikimedia.org/wiki/File:South_Beach_palms_%28Unsplash%29.jpg), CC0.

**palm** is a fast and simple subdomain live checker with a little Miami breeze.

It reads subdomains from stdin or a `.txt` file, removes duplicates, normalizes messy tool output, and checks whether targets are live with DNS and/or HTTP probes.

## Why palm?

- Pipe-friendly: `subfinder -d example.com -silent | palm`
- File-friendly: `palm subs.txt`
- Fast enough for daily recon
- Simple output for chaining into other tools
- Turkish and English help output
- Tiny easter egg hidden under the shade

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

## Quick Start

```bash
palm subs.txt
palm subs.txt -status
palm subs.txt -mc 200,301,302 -title -server
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
-takeover          check subdomain takeover fingerprints
-q                 only print live hosts/URLs
-tools             show common tool pipelines
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
