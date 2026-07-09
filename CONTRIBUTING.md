# Contributing

Thanks for helping improve `palm`.

## Development

```bash
git clone https://github.com/kaaangumus/palm.git
cd palm
go test ./...
go vet ./...
go build -o palm .
```

## Pull Requests

- Keep changes focused.
- Add or update tests for behavior changes.
- Update README examples when flags or output change.
- Run `gofmt`, `go test ./...`, and `go vet ./...` before opening a PR.

## Fingerprints

Subdomain takeover fingerprints should be conservative. Prefer provider-specific CNAME patterns plus provider-specific error body text to reduce false positives.
