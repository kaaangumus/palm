package main

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var version = "0.6.3"

const modulePath = "github.com/kaaangumus/palm"
const latestReleaseURL = "https://api.github.com/repos/kaaangumus/palm/releases/latest"

type config struct {
	inputFile       string
	outputFile      string
	mode            string
	concurrency     int
	timeout         time.Duration
	resolverFile    string
	jsonOut         bool
	status          bool
	title           bool
	server          bool
	contentLen      bool
	responseTime    bool
	location        bool
	followRedirects bool
	method          string
	headers         http.Header
	takeover        bool
	quiet           bool
	tlsInfo         bool
	wildcard        bool
	filterWildcard  bool
	lang            string
	rate            float64
	delay           time.Duration
	limiter         *rateLimiter
	noSort          bool
	noScheme        bool
	progress        bool
	progressOut     io.Writer
	matchCodes      map[int]struct{}
	filterCodes     map[int]struct{}
}

type result struct {
	Host           string   `json:"host"`
	Live           bool     `json:"live"`
	DNS            bool     `json:"dns"`
	IPs            []string `json:"ips,omitempty"`
	URL            string   `json:"url,omitempty"`
	ProbedURL      string   `json:"probed_url,omitempty"`
	StatusCode     int      `json:"status_code,omitempty"`
	Title          string   `json:"title,omitempty"`
	Server         string   `json:"server,omitempty"`
	Length         *int64   `json:"content_length,omitempty"`
	ResponseTimeMS *int64   `json:"response_time_ms,omitempty"`
	Location       string   `json:"location,omitempty"`
	Takeover       bool     `json:"takeover,omitempty"`
	Provider       string   `json:"takeover_provider,omitempty"`
	CNAME          string   `json:"cname,omitempty"`
	Wildcard       bool     `json:"wildcard,omitempty"`
	TLSIssuer      string   `json:"tls_issuer,omitempty"`
	TLSExpires     string   `json:"tls_expires,omitempty"`
	TLSDaysLeft    *int     `json:"tls_days_left,omitempty"`
	TLSMismatch    bool     `json:"tls_mismatch,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type httpProbe struct {
	URL            string
	FinalURL       string
	StatusCode     int
	Title          string
	Server         string
	Length         *int64
	ResponseTimeMS *int64
	Location       string
	TLSIssuer      string
	TLSExpires     string
	TLSDaysLeft    *int
	TLSMismatch    bool
}

type releaseInfo struct {
	TagName string         `json:"tag_name"`
	URL     string         `json:"html_url"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ",")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type resolverPool struct {
	addrs     []string
	resolvers []*net.Resolver
	next      uint64
}

// rateLimiter spaces HTTP requests so a scan stays polite. A nil limiter means
// no limit. The zero value is not usable; build it with newRateLimiter.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// newRateLimiter builds a limiter from -rate (requests per second) and -delay
// (minimum gap). A non-positive rate and delay means unlimited.
func newRateLimiter(rate float64, delay time.Duration) *rateLimiter {
	interval := time.Duration(0)
	if rate > 0 {
		interval = time.Duration(float64(time.Second) / rate)
	}
	if delay > interval {
		interval = delay
	}
	if interval <= 0 {
		return nil
	}
	return &rateLimiter{interval: interval}
}

// Wait blocks until the next request slot is due, or ctx is done.
func (l *rateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type takeoverFingerprint struct {
	Provider string
	CNAMEs   []string
	Bodies   []string
}

type wildcardCache struct {
	pool    *resolverPool
	timeout time.Duration
	mu      sync.Mutex
	entries map[string]*wildcardEntry
}

type wildcardEntry struct {
	once sync.Once
	ips  []string
}

func newWildcardCache(pool *resolverPool, timeout time.Duration) *wildcardCache {
	return &wildcardCache{pool: pool, timeout: timeout, entries: make(map[string]*wildcardEntry)}
}

func (w *wildcardCache) entry(parent string) *wildcardEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.entries[parent]
	if !ok {
		e = &wildcardEntry{}
		w.entries[parent] = e
	}
	return e
}

// matches reports whether a resolvable random name under the host's parent
// domain resolves to an address the host also uses, which means the name exists
// because of a wildcard record rather than a real subdomain.
func (w *wildcardCache) matches(ctx context.Context, ips []string, host string) bool {
	if w == nil || len(ips) == 0 {
		return false
	}
	parent := parentDomain(host)
	if parent == "" {
		return false
	}
	e := w.entry(parent)
	e.once.Do(func() {
		probeCtx, cancel := context.WithTimeout(ctx, w.timeout)
		defer cancel()
		random := randomLabel() + "." + parent
		if resolved, err := lookupHostWithCtx(probeCtx, random, w.pool); err == nil {
			e.ips = resolved
		}
	})
	return ipSetsOverlap(ips, e.ips)
}

func randomLabel() string {
	var raw [8]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return "palm-wildcard-probe"
	}
	return "palm" + hex.EncodeToString(raw[:])
}

// parentDomain returns the registrable-ish parent used for a wildcard probe.
// It is a heuristic (no public suffix list): aaa.bbb.example.com -> example.com
// and aaa.bbb.example.co.uk -> example.co.uk. Shared hosting suffixes such as
// github.io return "", because probing them would flag every real project site
// as a wildcard.
func parentDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return ""
	}
	keep := 2
	tld := labels[len(labels)-1]
	second := labels[len(labels)-2]
	if len(tld) == 2 && len(labels) >= 4 && isCommonSecondLevel(second) {
		keep = 3
	}
	parent := strings.Join(labels[len(labels)-keep:], ".")
	if isSharedSuffix(parent) {
		return ""
	}
	return parent
}

// sharedSuffixes are hosting suffixes where any label resolves, so a wildcard
// probe against them proves nothing about a real subdomain.
var sharedSuffixes = map[string]struct{}{
	"amazonaws.com":          {},
	"appspot.com":            {},
	"azurefd.net":            {},
	"azurewebsites.net":      {},
	"blogspot.com":           {},
	"cloudapp.net":           {},
	"cloudfront.net":         {},
	"digitaloceanspaces.com": {},
	"firebaseapp.com":        {},
	"fly.dev":                {},
	"gitbook.io":             {},
	"github.io":              {},
	"gitlab.io":              {},
	"glitch.me":              {},
	"herokuapp.com":          {},
	"herokudns.com":          {},
	"linodeobjects.com":      {},
	"myshopify.com":          {},
	"netlify.app":            {},
	"ngrok-free.app":         {},
	"ngrok.io":               {},
	"notion.site":            {},
	"onrender.com":           {},
	"pages.dev":              {},
	"readme.io":              {},
	"repl.co":                {},
	"run.app":                {},
	"storage.googleapis.com": {},
	"surge.sh":               {},
	"trafficmanager.net":     {},
	"vercel.app":             {},
	"web.app":                {},
	"weebly.com":             {},
	"wixsite.com":            {},
	"wordpress.com":          {},
	"workers.dev":            {},
	"zendesk.com":            {},
}

func isSharedSuffix(parent string) bool {
	_, ok := sharedSuffixes[strings.ToLower(strings.TrimSuffix(parent, "."))]
	return ok
}

func isCommonSecondLevel(label string) bool {
	switch label {
	case "co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go", "mil", "sch":
		return true
	}
	return false
}

func ipSetsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(b))
	for _, ip := range b {
		set[ip] = struct{}{}
	}
	for _, ip := range a {
		if _, ok := set[ip]; ok {
			return true
		}
	}
	return false
}

var takeoverFingerprints = []takeoverFingerprint{
	{Provider: "aws-s3", CNAMEs: []string{"s3.amazonaws.com", "s3-website", "amazonaws.com"}, Bodies: []string{"nosuchbucket", "the specified bucket does not exist"}},
	{Provider: "github-pages", CNAMEs: []string{"github.io"}, Bodies: []string{"there isn't a github pages site here"}},
	{Provider: "heroku", CNAMEs: []string{"herokuapp.com", "herokudns.com"}, Bodies: []string{"no such app", "heroku | no such app"}},
	{Provider: "netlify", CNAMEs: []string{"netlify.app", "netlifyglobalcdn.com"}, Bodies: []string{"not found - request id"}},
	{Provider: "vercel", CNAMEs: []string{"vercel-dns.com", "vercel.app"}, Bodies: []string{"the deployment could not be found"}},
	{Provider: "azure", CNAMEs: []string{"azurewebsites.net", "cloudapp.net", "trafficmanager.net"}, Bodies: []string{"404 web site not found"}},
	{Provider: "fastly", CNAMEs: []string{"fastly.net"}, Bodies: []string{"fastly error: unknown domain"}},
	{Provider: "shopify", CNAMEs: []string{"myshopify.com"}, Bodies: []string{"sorry, this shop is currently unavailable"}},
	{Provider: "zendesk", CNAMEs: []string{"zendesk.com"}, Bodies: []string{"help center closed", "oops, this help center no longer exists"}},
	{Provider: "readme", CNAMEs: []string{"readme.io"}, Bodies: []string{"project doesnt exist", "project doesn't exist"}},
}

var (
	errInterrupted = errors.New("interrupted")
	lookPath       = exec.LookPath
)

func main() {
	// Go's HTTP transport can log noisy "Unsolicited response received on idle
	// HTTP channel" lines to stderr. palm has no logging of its own, so keep the
	// stream clean for pipelines.
	log.SetOutput(io.Discard)

	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, errInterrupted) {
			fmt.Fprintln(os.Stderr, "palm:", err)
			os.Exit(130)
		}
		fatal(err)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}
	cfg.progressOut = stderr
	if cfg.inputFile == "" && stdinIsTerminal() {
		fmt.Fprint(stdout, usageLang(cfg.lang))
		return nil
	}

	hosts, err := readHosts(cfg.inputFile, stdin)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	out, err := openResultWriter(cfg.outputFile, stdout)
	if err != nil {
		return err
	}
	defer out.Abort()

	var runErr error
	if cfg.noSort {
		// Same filters and formatting, written as each host finishes.
		runErr = runChecks(ctx, hosts, cfg, func(res result) error {
			return writeResult(out, res, cfg)
		})
	} else {
		var collected []result
		runErr = runChecks(ctx, hosts, cfg, func(res result) error {
			collected = append(collected, res)
			return nil
		})
		if runErr == nil {
			sortResults(collected)
			runErr = writeResults(out, collected, cfg)
		}
	}
	if runErr != nil {
		if isBrokenPipe(runErr) {
			return nil
		}
		return runErr
	}
	if err := out.Commit(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return errInterrupted
	}
	return nil
}

func parseFlags(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("palm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.inputFile, "l", "", "subdomain list file")
	fs.StringVar(&cfg.inputFile, "list", "", "subdomain list file")
	fs.StringVar(&cfg.outputFile, "o", "", "output file")
	fs.StringVar(&cfg.mode, "mode", "both", "check mode: dns, http, both")
	fs.StringVar(&cfg.resolverFile, "r", "", "resolver file for DNS lookups and HTTP dials")
	fs.IntVar(&cfg.concurrency, "c", 100, "concurrent workers")
	timeout := fs.Int("timeout", 5, "timeout in seconds per phase (DNS, HTTP)")
	matchCodes := fs.String("mc", "", "match HTTP status codes")
	filterCodes := fs.String("fc", "", "filter HTTP status codes")
	var headers headerFlags
	fs.BoolVar(&cfg.jsonOut, "json", false, "write JSON lines")
	fs.BoolVar(&cfg.status, "status", false, "include HTTP status in text output")
	fs.BoolVar(&cfg.title, "title", false, "include page title")
	fs.BoolVar(&cfg.server, "server", false, "include server header")
	fs.BoolVar(&cfg.contentLen, "cl", false, "include content length")
	fs.BoolVar(&cfg.responseTime, "rt", false, "include response time")
	fs.BoolVar(&cfg.location, "location", false, "include redirect location")
	fs.BoolVar(&cfg.followRedirects, "follow-redirects", true, "follow HTTP redirects")
	fs.StringVar(&cfg.method, "method", "", "HTTP method")
	fs.Var(&headers, "H", "custom HTTP header, repeatable")
	fs.BoolVar(&cfg.takeover, "takeover", false, "check subdomain takeover fingerprints")
	fs.BoolVar(&cfg.tlsInfo, "tls", false, "include TLS certificate summary")
	fs.BoolVar(&cfg.wildcard, "wildcard", false, "detect wildcard DNS and mark matching hosts")
	fs.BoolVar(&cfg.filterWildcard, "fw", false, "drop hosts that match a wildcard DNS record")
	fs.BoolVar(&cfg.quiet, "q", false, "only print live hosts/URLs")
	lang := fs.String("lang", "", "help language: en, tr (default: auto)")
	fs.Float64Var(&cfg.rate, "rate", 0, "max HTTP requests per second (0 = unlimited)")
	fs.DurationVar(&cfg.delay, "delay", 0, "minimum delay between HTTP requests, e.g. 200ms")
	fs.BoolVar(&cfg.noSort, "no-sort", false, "print results in completion order instead of host order")
	fs.BoolVar(&cfg.noScheme, "no-scheme", false, "omit the http:// or https:// prefix in text output")
	fs.BoolVar(&cfg.progress, "progress", false, "print progress to stderr")
	showHelp := fs.Bool("h", false, "show help")
	fs.BoolVar(showHelp, "help", false, "show help")
	showVersion := fs.Bool("version", false, "show version")
	checkUpdate := fs.Bool("check-update", false, "check latest GitHub release")
	runUpdate := fs.Bool("update", false, "self-update to the latest release")
	showTools := fs.Bool("tools", false, "show common tool pipelines")
	showMiami := fs.Bool("miami", false, "show the Miami easter egg")

	if err := fs.Parse(reorderArgs(args)); err != nil {
		return cfg, usageError(*lang)
	}
	cfg.lang = strings.ToLower(strings.TrimSpace(*lang))
	switch cfg.lang {
	case "", "en", "tr":
	default:
		return cfg, fmt.Errorf("invalid -lang: %s (use en or tr)", *lang)
	}
	if *showHelp {
		fmt.Fprint(os.Stdout, usageLang(cfg.lang))
		os.Exit(0)
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, "palm "+version)
		os.Exit(0)
	}
	if *checkUpdate {
		if err := checkForUpdate(os.Stdout); err != nil {
			return cfg, err
		}
		os.Exit(0)
	}
	if *runUpdate {
		if err := updatePalm(os.Stdout, os.Stderr); err != nil {
			return cfg, err
		}
		os.Exit(0)
	}
	if *showTools {
		fmt.Fprint(os.Stdout, localizedToolsUsageLang(cfg.lang))
		os.Exit(0)
	}
	if *showMiami {
		fmt.Fprint(os.Stdout, miamiEgg())
		os.Exit(0)
	}
	if cfg.inputFile == "" && fs.NArg() > 0 {
		cfg.inputFile = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		return cfg, errors.New("only one input file can be provided")
	}
	if cfg.concurrency < 1 {
		return cfg, errors.New("concurrency must be greater than 0")
	}
	if *timeout < 1 {
		return cfg, errors.New("timeout must be greater than 0")
	}
	if cfg.rate < 0 {
		return cfg, errors.New("rate must be zero or greater")
	}
	if cfg.delay < 0 {
		return cfg, errors.New("delay must be zero or greater")
	}
	cfg.limiter = newRateLimiter(cfg.rate, cfg.delay)
	var err error
	cfg.headers, err = parseHeaders(headers)
	if err != nil {
		return cfg, err
	}
	cfg.method = strings.ToUpper(strings.TrimSpace(cfg.method))
	if cfg.method != "" && !validHTTPMethod(cfg.method) {
		return cfg, fmt.Errorf("invalid -method: %s", cfg.method)
	}
	cfg.matchCodes, err = parseCodes(*matchCodes)
	if err != nil {
		return cfg, fmt.Errorf("invalid -mc: %w", err)
	}
	cfg.filterCodes, err = parseCodes(*filterCodes)
	if err != nil {
		return cfg, fmt.Errorf("invalid -fc: %w", err)
	}
	cfg.timeout = time.Duration(*timeout) * time.Second
	cfg.mode = strings.ToLower(strings.TrimSpace(cfg.mode))
	switch cfg.mode {
	case "dns", "http", "both":
	default:
		return cfg, errors.New("mode must be one of: dns, http, both")
	}
	if (cfg.wildcard || cfg.filterWildcard) && cfg.mode == "http" {
		return cfg, errors.New("-wildcard and -fw require -mode dns or both")
	}
	return cfg, nil
}

func reorderArgs(args []string) []string {
	valueFlags := map[string]struct{}{
		"-l": {}, "-list": {}, "-o": {}, "-mode": {}, "-r": {}, "-c": {}, "-timeout": {}, "-mc": {}, "-fc": {}, "-method": {}, "-H": {}, "-lang": {},
		"-rate": {}, "-delay": {},
	}

	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}

		flags = append(flags, arg)
		name := arg
		if idx := strings.IndexByte(arg, '='); idx >= 0 {
			name = arg[:idx]
		}
		if _, ok := valueFlags[name]; ok && !strings.Contains(arg, "=") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

func parseHeaders(values []string) (http.Header, error) {
	headers := make(http.Header)
	for _, value := range values {
		name, headerValue, ok := strings.Cut(value, ":")
		if !ok {
			return nil, fmt.Errorf("invalid -H header %q, expected 'Name: value'", value)
		}
		name = strings.TrimSpace(name)
		headerValue = strings.TrimSpace(headerValue)
		if name == "" || strings.ContainsAny(name, " \t\r\n:") {
			return nil, fmt.Errorf("invalid -H header name %q", name)
		}
		headers.Add(name, headerValue)
	}
	return headers, nil
}

func validHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func parseCodes(raw string) (map[int]struct{}, error) {
	codes := make(map[int]struct{})
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return codes, nil
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		code, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		if code < 100 || code > 999 {
			return nil, fmt.Errorf("%d is outside HTTP status range", code)
		}
		codes[code] = struct{}{}
	}
	return codes, nil
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func checkForUpdate(w io.Writer) error {
	latest, err := latestRelease()
	if err != nil {
		return err
	}
	fmtCheckVersion(w, latest)
	return nil
}

func fmtCheckVersion(w io.Writer, latest releaseInfo) {
	latestVersion := strings.TrimPrefix(latest.TagName, "v")
	fmt.Fprintf(w, "current: %s\n", version)
	fmt.Fprintf(w, "latest:  %s\n", latestVersion)
	if latestVersion == version {
		fmt.Fprintln(w, "palm is up to date")
		return
	}
	fmt.Fprintf(w, "update:  palm -update\n")
	if latest.URL != "" {
		fmt.Fprintf(w, "release: %s\n", latest.URL)
	}
}

func latestRelease() (releaseInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return releaseInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "palm/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return releaseInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return releaseInfo{}, fmt.Errorf("GitHub release check failed: %s", resp.Status)
	}
	var latest releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&latest); err != nil {
		return releaseInfo{}, err
	}
	if latest.TagName == "" {
		return releaseInfo{}, errors.New("GitHub release check returned an empty tag")
	}
	return latest, nil
}

func updatePalm(stdout, stderr io.Writer) error {
	latest, err := latestRelease()
	if err != nil {
		return err
	}
	return updatePalmTo(stdout, stderr, latest)
}

func updatePalmTo(stdout, stderr io.Writer, latest releaseInfo) error {
	latestVersion := strings.TrimPrefix(latest.TagName, "v")
	if latestVersion == version {
		fmt.Fprintf(stdout, "palm %s is already the latest release\n", version)
		return nil
	}

	fmt.Fprintf(stdout, "updating palm %s -> %s\n", version, latestVersion)
	if err := selfUpdate(latest, stdout); err == nil {
		fmt.Fprintln(stdout, "update complete")
		fmt.Fprintln(stdout, "restart your shell or run `hash -r` if your shell cached the old binary")
		return nil
	} else {
		fmt.Fprintf(stderr, "self-update failed: %v\n", err)
	}

	if _, err := lookPath("go"); err == nil {
		fmt.Fprintf(stdout, "falling back to: go install %s@latest\n", modulePath)
		cmd := exec.Command("go", "install", modulePath+"@latest")
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "update complete")
		fmt.Fprintln(stdout, "restart your shell or run `hash -r` if your shell cached the old binary")
		return nil
	}

	fmt.Fprintln(stdout, "go command not found; palm was probably installed from a release binary.")
	fmt.Fprintln(stdout, "update with the installer for your platform:")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  Windows (PowerShell):")
	fmt.Fprintln(stdout, "    irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  Linux / macOS:")
	fmt.Fprintln(stdout, "    curl -fsSL https://raw.githubusercontent.com/kaaangumus/palm/main/install.sh | sh")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "release page: https://github.com/kaaangumus/palm/releases")
	return nil
}

// assetNameFor maps a platform to the release asset name produced by the
// release workflow.
func assetNameFor(goos, goarch string) string {
	name := "palm_" + goos + "_" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

func findAsset(assets []releaseAsset, name string) (releaseAsset, bool) {
	for _, asset := range assets {
		if asset.Name == name {
			return asset, true
		}
	}
	return releaseAsset{}, false
}

// selfUpdate replaces the running executable with the release asset for this
// platform. The download is verified against checksums.txt when it is published
// and the new binary must report the expected version before it is swapped in.
func selfUpdate(latest releaseInfo, stdout io.Writer) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	assetName := assetNameFor(runtime.GOOS, runtime.GOARCH)
	asset, ok := findAsset(latest.Assets, assetName)
	if !ok {
		return fmt.Errorf("release %s has no %s asset", latest.TagName, assetName)
	}

	dir := filepath.Dir(exe)
	if err := checkWritable(dir); err != nil {
		return fmt.Errorf("%s is not writable (%v); retry with sudo", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".palm-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	fmt.Fprintf(stdout, "downloading %s\n", assetName)
	if err := downloadTo(tmp, asset.URL); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if expected, err := publishedChecksum(latest, assetName); err == nil && expected != "" {
		sum, err := fileSHA256(tmpPath)
		if err != nil {
			return err
		}
		if !strings.EqualFold(sum, expected) {
			return fmt.Errorf("checksum mismatch for %s", assetName)
		}
		fmt.Fprintln(stdout, "checksum verified")
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil && runtime.GOOS != "windows" {
		return err
	}

	wantVersion := strings.TrimPrefix(latest.TagName, "v")
	if out, err := exec.Command(tmpPath, "-version").Output(); err == nil {
		if !strings.Contains(string(out), wantVersion) {
			return fmt.Errorf("downloaded binary reports %q, expected %s", strings.TrimSpace(string(out)), wantVersion)
		}
	}

	if err := replaceExecutable(tmpPath, exe); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".palm-write-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name)
}

func downloadTo(dst *os.File, url string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "palm/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	_, err = io.Copy(dst, resp.Body)
	return err
}

// publishedChecksum returns the sha256 for an asset from checksums.txt, which
// the release workflow publishes next to the binaries.
func publishedChecksum(latest releaseInfo, assetName string) (string, error) {
	checksums, ok := findAsset(latest.Assets, "checksums.txt")
	if !ok {
		return "", nil
	}
	client := &http.Client{Timeout: time.Minute}
	req, err := http.NewRequest(http.MethodGet, checksums.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "palm/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksums download failed: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return parseChecksums(string(data), assetName), nil
}

// parseChecksums reads "hash  filename" lines, the format of sha256sum output.
func parseChecksums(text, assetName string) string {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == assetName {
			return fields[0]
		}
	}
	return ""
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// replaceExecutable swaps the running binary. Renaming the old file aside first
// keeps the operation recoverable and works on Windows, where a running image
// can be renamed but not overwritten.
func replaceExecutable(newPath, target string) error {
	backup := target + ".old"
	_ = os.Remove(backup)

	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := os.Rename(newPath, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func usageError(lang string) error {
	return errors.New(strings.TrimSpace(usageLang(lang)))
}

func usage() string {
	return usageLang("")
}

// usageLang picks the help language: "en" and "tr" force one, anything else
// (including "") follows the locale.
func usageLang(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "tr":
		return trUsageFresh()
	case "en":
		return enUsage()
	}
	if isTurkishLocale() {
		return trUsageFresh()
	}
	return enUsage()
}

func enUsage() string {
	return `palm - fast subdomain live checker

Usage:
  subfinder -d example.com -silent | palm
  palm subs.txt
  dnsx -l subs.txt -silent | palm -mode http -status
  palm subs.txt -mc 200,301,302 -title -server
  palm -l subs.txt -mode both -json -o live.jsonl

Flags:
  -l, -list string   subdomain list file
  -o string          output file
  -mode string       dns, http, both (default "both")
  -r string          resolver file for DNS lookups and HTTP dials
  -c int             concurrent workers (default 100)
  -timeout int       timeout in seconds per phase (DNS, HTTP) (default 5)
  -mc string         match HTTP status codes, comma-separated
  -fc string         filter HTTP status codes, comma-separated
  -json              write JSON lines
  -status            include HTTP status in text output
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
`
}

func trUsageFresh() string {
	return `palm - hizli subdomain live checker

Kullanim:
  subfinder -d example.com -silent | palm
  palm subs.txt
  dnsx -l subs.txt -silent | palm -mode http -status
  palm subs.txt -mc 200,301,302 -title -server
  palm subs.txt -rt -location -follow-redirects=false
  palm -l subs.txt -mode both -json -o live.jsonl

Parametreler:
  -l, -list string   subdomain liste dosyasi
  -o string          cikti dosyasi
  -mode string       kontrol modu: dns, http, both (varsayilan "both")
  -r string          DNS sorgulari ve HTTP baglantilari icin resolver dosyasi
  -c int             eszamanli worker sayisi (varsayilan 100)
  -timeout int       asama basina saniye cinsinden timeout: DNS, HTTP (varsayilan 5)
  -mc string         eslesecek HTTP status kodlari, virgulle ayrilir
  -fc string         filtrelenecek HTTP status kodlari, virgulle ayrilir
  -json              JSON lines formatinda yaz
  -status            text ciktida HTTP status veya DNS IP bilgisini goster
  -title             sayfa basligini goster
  -server            server header bilgisini goster
  -cl                content length bilgisini goster
  -rt                response time bilgisini goster
  -location          redirect Location header bilgisini goster
  -follow-redirects  HTTP redirect takip et (varsayilan true)
  -method string     HTTP method
  -H string          custom HTTP header, tekrar edilebilir
  -takeover          subdomain takeover fingerprint kontrolu yap
  -tls               TLS sertifika ozetini goster
  -wildcard          wildcard DNS tespit et ve eslesen hostlari isaretle
  -fw                wildcard DNS kaydiyla eslesen hostlari ele
  -q                 sadece live URL yaz, sade ve pipe dostu
  -no-sort           host sirasi yerine tamamlanma sirasina gore yaz
  -no-scheme         text ciktida http:// veya https:// onekini kaldir
  -progress          stderr'e ilerleme yaz
  -rate float        saniyedeki en fazla HTTP istegi (0 = sinirsiz)
  -delay duration    HTTP istekleri arasi en az bekleme, orn. 200ms
  -lang string       yardim dili: en, tr (varsayilan: otomatik)
  -tools             yaygin araclarla ornek pipeline goster
  -check-update      en son GitHub release surumunu kontrol et
  -update            palm'i son surume kendi kendine guncelle
  -version           surumu goster
  -h, -help          yardimi goster
`
}

func isTurkishLocale() bool {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"} {
		locale := strings.ToLower(os.Getenv(key))
		if strings.HasPrefix(locale, "tr") {
			return true
		}
	}
	return false
}

func localizedToolsUsage() string {
	return localizedToolsUsageLang("")
}

func localizedToolsUsageLang(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "tr":
		return trToolsUsage()
	case "en":
		return toolsUsage()
	}
	if isTurkishLocale() {
		return trToolsUsage()
	}
	return toolsUsage()
}

func trToolsUsage() string {
	return `palm ile yaygin arac ornekleri:

  subfinder -d example.com -silent | palm
  assetfinder --subs-only example.com | palm
  amass enum -passive -d example.com | palm
  findomain -t example.com -q | palm
  chaos -d example.com -silent | palm

Not: palm stdin'den okur, txt dosyasi da kabul eder: palm subs.txt
`
}

func toolsUsage() string {
	return `Common tool pipelines for palm:

  subfinder -d example.com -silent | palm
  assetfinder --subs-only example.com | palm
  amass enum -passive -d example.com | palm
  findomain -t example.com -q | palm
  chaos -d example.com -silent | palm

Tip: palm reads stdin and accepts txt files too: palm subs.txt
`
}

func miamiEgg() string {
	return `
  ____   _    _     __  __
 |  _ \ / \  | |   |  \/  |
 | |_) / _ \ | |   | |\/| |
 |  __/ ___ \| |___| |  | |
 |_| /_/   \_\_____|_|  |_|

        Miami mode: on
        Easter egg: Kaan Gumus
`
}
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "palm:", err)
	os.Exit(1)
}

func readHosts(path string, stdin io.Reader) ([]string, error) {
	var r io.Reader
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("%w (to scan a single host, pipe it in: echo host | palm)", err)
			}
			return nil, err
		}
		defer f.Close()
		r = f
	} else {
		r = stdin
	}

	seen := make(map[string]struct{})
	var hosts []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		host := normalizeHost(scanner.Text())
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(hosts)
	return hosts, nil
}

func normalizeHost(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	// Tools such as dnsx can emit "host ip"; keep the host-like first field.
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	raw := strings.Trim(fields[0], " ,;(){}'\"")
	if raw == "" {
		return ""
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil {
			raw = u.Host
		}
	}

	raw = strings.TrimSuffix(raw, ".")
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = raw[1 : len(raw)-1]
	}
	raw = strings.Trim(strings.ToLower(raw), " .")
	if raw == "" || strings.ContainsAny(raw, `/\`) {
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ""
	}
	return raw
}

type resultWriter struct {
	w         io.Writer
	file      *os.File
	tmpPath   string
	finalPath string
	committed bool
}

// openResultWriter keeps the destination untouched until Commit, so an
// interrupted or failed scan never truncates an existing output file.
func openResultWriter(path string, stdout io.Writer) (*resultWriter, error) {
	if path == "" {
		return &resultWriter{w: stdout}, nil
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".palm-*.tmp")
	if err != nil {
		return nil, err
	}
	return &resultWriter{w: f, file: f, tmpPath: f.Name(), finalPath: path}, nil
}

func (rw *resultWriter) Write(p []byte) (int, error) {
	return rw.w.Write(p)
}

func (rw *resultWriter) Commit() error {
	if rw.file == nil {
		return nil
	}
	if err := rw.file.Close(); err != nil {
		rw.file = nil
		_ = os.Remove(rw.tmpPath)
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(rw.finalPath); err == nil {
		mode = info.Mode().Perm()
	}
	_ = os.Chmod(rw.tmpPath, mode)
	if err := os.Rename(rw.tmpPath, rw.finalPath); err != nil {
		rw.file = nil
		_ = os.Remove(rw.tmpPath)
		return err
	}
	rw.file = nil
	rw.committed = true
	return nil
}

func (rw *resultWriter) Abort() {
	if rw.file == nil || rw.committed {
		return
	}
	_ = rw.file.Close()
	_ = os.Remove(rw.tmpPath)
	rw.file = nil
}

func runChecks(ctx context.Context, hosts []string, cfg config, emit func(result) error) error {
	if emit == nil {
		emit = func(result) error { return nil }
	}
	resolvers, err := loadResolverPool(cfg.resolverFile)
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan string)
	results := make(chan result, cfg.concurrency)

	var wildcards *wildcardCache
	if cfg.wildcard || cfg.filterWildcard {
		wildcards = newWildcardCache(resolvers, cfg.timeout)
	}

	client := newHTTPClient(cfg, resolvers)

	var progress *progressState
	if cfg.progress && cfg.progressOut != nil {
		progress = &progressState{total: len(hosts), start: time.Now()}
		stopProgress := make(chan struct{})
		progressDone := make(chan struct{})
		go func() {
			defer close(progressDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					fmt.Fprintln(cfg.progressOut, progress.line())
				case <-stopProgress:
					return
				}
			}
		}()
		defer func() {
			close(stopProgress)
			<-progressDone
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				res := checkHost(runCtx, host, cfg, client, resolvers, wildcards)
				select {
				case results <- res:
				case <-runCtx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			select {
			case jobs <- host:
			case <-runCtx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var emitErr error
	for res := range results {
		if progress != nil {
			progress.add(res)
		}
		if emitErr != nil {
			continue // drain so the workers can finish
		}
		if err := emit(res); err != nil {
			emitErr = err
			cancel()
		}
	}
	if progress != nil && emitErr == nil {
		fmt.Fprintln(cfg.progressOut, progress.line())
	}
	return emitErr
}

// progressState tracks scan counters for -progress. The results loop is the
// only writer, so the mutex protects readers only.
type progressState struct {
	mu     sync.Mutex
	total  int
	done   int
	live   int
	failed int
	start  time.Time
}

func (p *progressState) add(res result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	if res.Live {
		p.live++
	} else {
		p.failed++
	}
}

func (p *progressState) line() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	percent := 0
	if p.total > 0 {
		percent = p.done * 100 / p.total
	}
	return fmt.Sprintf("palm: %d/%d checked (%d%%), %d live, %d failed, %s",
		p.done, p.total, percent, p.live, p.failed, time.Since(p.start).Round(time.Second))
}

func newHTTPClient(cfg config, resolvers *resolverPool) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// Setting a custom TLSClientConfig disables Go's automatic HTTP/2
		// upgrade; ForceAttemptHTTP2 keeps h2 for hosts that support it.
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        cfg.concurrency * 2,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	if resolvers != nil {
		transport.DialContext = resolvers.dialContext(cfg.timeout)
	}

	client := &http.Client{
		Timeout:   cfg.timeout,
		Transport: transport,
	}
	if !cfg.followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func sortResults(out []result) {
	sort.Slice(out, func(i, j int) bool {
		return out[i].Host < out[j].Host
	})
}

func checkHost(ctx context.Context, host string, cfg config, client *http.Client, resolvers *resolverPool, wildcards *wildcardCache) result {
	res := result{Host: host}

	if cfg.mode == "dns" || cfg.mode == "both" {
		ips, err := lookupHost(ctx, host, cfg.timeout, resolvers)
		if err == nil && len(ips) > 0 {
			res.DNS = true
			res.IPs = ips
			res.Live = true
			if wildcards != nil && wildcards.matches(ctx, ips, host) {
				res.Wildcard = true
			}
		} else {
			res.Error = shortErr(err)
			res.Live = false
			return res
		}
	}

	if cfg.mode == "http" || cfg.mode == "both" {
		// Both schemes are probed in parallel under one budget, so a host that
		// blackholes 443 still gets its HTTP chance within -timeout.
		httpCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
		probe, err := checkHTTP(httpCtx, host, cfg, client)
		cancel()
		if err == nil {
			res.Live = true
			res.URL = probe.FinalURL
			res.ProbedURL = probe.URL
			res.StatusCode = probe.StatusCode
			res.Title = probe.Title
			res.Server = probe.Server
			res.Length = probe.Length
			res.ResponseTimeMS = probe.ResponseTimeMS
			res.Location = probe.Location
			res.TLSIssuer = probe.TLSIssuer
			res.TLSExpires = probe.TLSExpires
			res.TLSDaysLeft = probe.TLSDaysLeft
			res.TLSMismatch = probe.TLSMismatch
			if !cfg.takeover {
				return res
			}
		} else {
			res.Live = false
			res.Error = shortErr(err)
		}
	}

	if cfg.takeover {
		takeover, provider, cname := detectTakeover(ctx, host, cfg.timeout, resolvers, client, cfg.limiter)
		res.CNAME = cname
		res.Takeover = takeover
		res.Provider = provider
		if takeover {
			res.Live = true
		}
	}

	return res
}

func lookupHost(ctx context.Context, host string, timeout time.Duration, resolvers *resolverPool) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return lookupHostWithCtx(lookupCtx, host, resolvers)
}

func lookupHostWithCtx(ctx context.Context, host string, resolvers *resolverPool) ([]string, error) {
	ips, err := resolvers.lookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	sort.Strings(ips)
	return ips, nil
}

func detectTakeover(ctx context.Context, host string, timeout time.Duration, resolvers *resolverPool, client *http.Client, limiter *rateLimiter) (bool, string, string) {
	takeoverCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cname, err := lookupCNAME(takeoverCtx, host, resolvers)
	if err != nil || cname == "" {
		return false, "", ""
	}
	return evaluateTakeover(takeoverCtx, host, cname, client, limiter)
}

// evaluateTakeover keeps the resolved CNAME even when no takeover fingerprint
// matches, so `-takeover -json` still shows the CNAME chain for manual review.
func evaluateTakeover(ctx context.Context, host, cname string, client *http.Client, limiter *rateLimiter) (bool, string, string) {
	fingerprint, ok := matchTakeoverCNAME(cname)
	if !ok {
		return false, "", cname
	}

	body := fetchTakeoverBody(ctx, host, client, limiter)
	if body == "" {
		return false, "", cname
	}
	if matchTakeoverBody(body, fingerprint) {
		return true, fingerprint.Provider, cname
	}
	return false, "", cname
}

func lookupCNAME(ctx context.Context, host string, resolvers *resolverPool) (string, error) {
	return resolvers.lookupCNAME(ctx, host)
}

func matchTakeoverCNAME(cname string) (takeoverFingerprint, bool) {
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, fp := range takeoverFingerprints {
		for _, pattern := range fp.CNAMEs {
			if cnameMatchesPattern(cname, strings.ToLower(pattern)) {
				return fp, true
			}
		}
	}
	return takeoverFingerprint{}, false
}

// cnameMatchesPattern matches whole DNS labels, so "amazonaws.com" does not
// match "notamazonaws.com". Patterns without a dot (such as "s3-website")
// match a label prefix, which covers "bucket.s3-website-us-east-1...".
func cnameMatchesPattern(cname, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, ".") {
		return cname == pattern || strings.HasSuffix(cname, "."+pattern)
	}
	for _, label := range strings.Split(cname, ".") {
		if label == pattern || strings.HasPrefix(label, pattern+"-") {
			return true
		}
	}
	return false
}

func fetchTakeoverBody(ctx context.Context, host string, client *http.Client, limiter *rateLimiter) string {
	for _, scheme := range []string{"https", "http"} {
		if err := limiter.Wait(ctx); err != nil {
			return ""
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "palm/"+version)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		_ = resp.Body.Close()
		if len(data) > 0 {
			return strings.ToLower(string(data))
		}
	}
	return ""
}

func matchTakeoverBody(body string, fp takeoverFingerprint) bool {
	body = strings.ToLower(body)
	for _, pattern := range fp.Bodies {
		if strings.Contains(body, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func newResolverPool(addrs []string) *resolverPool {
	resolvers := make([]*net.Resolver, 0, len(addrs))
	for _, addr := range addrs {
		addr := addr
		resolvers = append(resolvers, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, "udp", addr)
			},
		})
	}
	return &resolverPool{addrs: addrs, resolvers: resolvers}
}

func loadResolverPool(path string) (*resolverPool, error) {
	if path == "" {
		return nil, nil
	}
	hosts, err := readRawLines(path)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, line := range hosts {
		addr := normalizeResolver(line)
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("resolver file has no usable resolvers")
	}
	return newResolverPool(addrs), nil
}

func readRawLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func normalizeResolver(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	line = strings.TrimSpace(fields[0])
	if line == "" {
		return ""
	}
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err == nil {
			line = u.Host
		}
	}
	host, port, err := net.SplitHostPort(line)
	if err == nil {
		if net.ParseIP(host) == nil || port == "" {
			return ""
		}
		return net.JoinHostPort(host, port)
	}
	if net.ParseIP(line) == nil {
		return ""
	}
	return net.JoinHostPort(line, "53")
}

func (p *resolverPool) lookupHost(ctx context.Context, host string) ([]string, error) {
	if p == nil || len(p.resolvers) == 0 {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	idx := atomic.AddUint64(&p.next, 1)
	return p.resolvers[int(idx-1)%len(p.resolvers)].LookupHost(ctx, host)
}

func (p *resolverPool) lookupCNAME(ctx context.Context, host string) (string, error) {
	if p == nil || len(p.resolvers) == 0 {
		return net.DefaultResolver.LookupCNAME(ctx, host)
	}
	idx := atomic.AddUint64(&p.next, 1)
	return p.resolvers[int(idx-1)%len(p.resolvers)].LookupCNAME(ctx, host)
}

// dialContext resolves the target through the pool, so -r applies to HTTP
// connections as well as to the DNS phase. IP literals are dialed directly.
func (p *resolverPool) dialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		ips, err := p.lookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no addresses for %s", host)
		}
		return nil, lastErr
	}
}

func checkHTTP(ctx context.Context, host string, cfg config, client *http.Client) (httpProbe, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		probe  httpProbe
		err    error
		scheme string
	}

	// Both schemes are probed at once under one budget, so a host that drops
	// port 443 still gets its HTTP chance. The winner is decided by preference,
	// never by which answer arrived first: HTTPS is used whenever it produced a
	// usable response, otherwise HTTP. A timer-based shortcut here made the
	// reported scheme differ between runs for the same host.
	ch := make(chan outcome, 2)
	for _, scheme := range []string{"https", "http"} {
		scheme := scheme
		go func() {
			probe, err := requestURL(ctx, scheme+"://"+host, cfg, client)
			ch <- outcome{probe: probe, err: err, scheme: scheme}
		}()
	}

	var httpOK *outcome
	var lastErr error
	for i := 0; i < 2; i++ {
		out := <-ch

		if out.err == nil && statusAllowed(out.probe.StatusCode, cfg) {
			if out.scheme == "https" {
				// Returning cancels the HTTP attempt through the deferred cancel.
				return out.probe, nil
			}
			httpCopy := out
			httpOK = &httpCopy
			// Keep waiting for the HTTPS outcome to make the choice deterministic.
			continue
		}

		if out.err != nil {
			lastErr = out.err
		} else {
			lastErr = fmt.Errorf("status %d did not match filters", out.probe.StatusCode)
		}
	}

	if httpOK != nil {
		return httpOK.probe, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable response")
	}
	return httpProbe{}, lastErr
}

func requestURL(ctx context.Context, target string, cfg config, client *http.Client) (httpProbe, error) {
	method := http.MethodHead
	autoMethod := cfg.method == ""
	if cfg.method != "" {
		method = cfg.method
	} else if cfg.title {
		method = http.MethodGet
	}
	probe, err := doRequest(ctx, target, method, cfg, client)
	if err != nil {
		// Some servers hang up or reset on HEAD. When the method was chosen
		// automatically and the failure is not a timeout (no budget left to
		// retry), try GET once before giving up on this scheme.
		if autoMethod && method == http.MethodHead && !isTimeoutErr(err) {
			if retry, retryErr := doRequest(ctx, target, http.MethodGet, cfg, client); retryErr == nil {
				return retry, nil
			}
		}
		return httpProbe{}, err
	}
	if autoMethod && method == http.MethodHead && (probe.StatusCode == http.StatusMethodNotAllowed || probe.StatusCode == http.StatusForbidden) {
		return doRequest(ctx, target, http.MethodGet, cfg, client)
	}
	return probe, nil
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func doRequest(ctx context.Context, target, method string, cfg config, client *http.Client) (httpProbe, error) {
	if err := cfg.limiter.Wait(ctx); err != nil {
		return httpProbe{}, err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return httpProbe{}, err
	}
	req.Header.Set("User-Agent", "palm/"+version)
	for name, values := range cfg.headers {
		req.Header.Del(name)
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return httpProbe{}, err
	}
	defer resp.Body.Close()

	probe := httpProbe{
		URL:        target,
		FinalURL:   resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
	}
	if cfg.responseTime {
		rt := elapsed.Milliseconds()
		probe.ResponseTimeMS = &rt
	}
	if cfg.location {
		probe.Location = resp.Header.Get("Location")
	}
	if cfg.contentLen && resp.ContentLength >= 0 {
		length := resp.ContentLength
		probe.Length = &length
	}
	if cfg.server {
		probe.Server = resp.Header.Get("Server")
	}
	if cfg.tlsInfo && resp.TLS != nil {
		applyTLSSummary(&probe, resp.TLS, target)
	}
	if cfg.title && method != http.MethodHead {
		// With redirects followed, the body belongs to the final URL. Only
		// attribute a title when the page is still served by the probed host,
		// otherwise a login page from another host would look like the
		// subdomain's own title.
		if sameHost(probe.URL, probe.FinalURL) {
			probe.Title = readTitle(resp.Body)
		}
	}
	return probe, nil
}

// applyTLSSummary records the leaf certificate of the probed URL. Validation is
// intentionally skipped for the request itself (self-signed hosts are common in
// recon), so the hostname match is checked here and reported separately.
func applyTLSSummary(probe *httpProbe, state *tls.ConnectionState, target string) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	probe.TLSIssuer = certIssuer(cert)
	probe.TLSExpires = cert.NotAfter.UTC().Format("2006-01-02")
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	probe.TLSDaysLeft = &days

	// The certificate belongs to the connection of the final URL: with redirects
	// followed, the last hop is the one that presented it.
	inspected := probe.FinalURL
	if inspected == "" {
		inspected = target
	}
	host := inspected
	if u, err := url.Parse(inspected); err == nil {
		host = u.Hostname()
	}
	probe.TLSMismatch = !certMatchesHost(cert, host)
}

func certIssuer(cert *x509.Certificate) string {
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		return cert.Issuer.Organization[0]
	}
	return cert.Issuer.CommonName
}

func certMatchesHost(cert *x509.Certificate, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, certIP := range cert.IPAddresses {
			if certIP.Equal(ip) {
				return true
			}
		}
		return false
	}
	if matchCertName(cert.Subject.CommonName, host) {
		return true
	}
	for _, name := range cert.DNSNames {
		if matchCertName(name, host) {
			return true
		}
	}
	return false
}

func matchCertName(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	if pattern == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func sameHost(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	ha := strings.ToLower(strings.TrimSuffix(ua.Hostname(), "."))
	hb := strings.ToLower(strings.TrimSuffix(ub.Hostname(), "."))
	// Hostname only: an http -> https upgrade keeps the same site, while a
	// redirect to another hostname is a different site even on a shared port.
	if ha == hb {
		return true
	}
	// www.example.com -> example.com is the same site, not a foreign page.
	return ha == "www."+hb || hb == "www."+ha
}

func statusAllowed(code int, cfg config) bool {
	if _, blocked := cfg.filterCodes[code]; blocked {
		return false
	}
	if len(cfg.matchCodes) == 0 {
		return true
	}
	_, ok := cfg.matchCodes[code]
	return ok
}

// titleReadLimit caps how much of a page palm reads while hunting for a title.
const titleReadLimit = 256 * 1024

// readTitle streams the body and stops as soon as the title is complete (or the
// head ends), instead of reading the whole capped body every time.
func readTitle(r io.Reader) string {
	s := titleScan{}
	chunk := make([]byte, 8192)
	for len(s.buf) < titleReadLimit {
		n, err := r.Read(chunk)
		if n > 0 {
			s.buf = append(s.buf, chunk[:n]...)
			if title, done := s.scan(); done {
				return title
			}
		}
		if err != nil {
			break
		}
	}
	title, _ := s.scan()
	return title
}

// titleScan finds a <title> element in a growing buffer without rescanning bytes
// it has already looked at. Each search remembers where it stopped and keeps one
// needle-length of overlap so a tag split across two reads is still found.
type titleScan struct {
	buf       []byte
	searchAt  int // next index to start searching for the current needle
	headAt    int // next index to start searching for </head>
	bodyStart int // first byte of the title text
	inBody    bool
}

func (s *titleScan) scan() (string, bool) {
	for {
		if !s.inBody {
			idx := indexFoldASCIIFrom(s.buf, "<title", s.searchAt)
			head := indexFoldASCIIFrom(s.buf, "</head>", s.headAt)
			// </head> before any <title means the head has no title.
			if idx < 0 || (head >= 0 && head < idx) {
				if head >= 0 {
					return "", true
				}
				s.searchAt = keepOverlap(s.buf, s.searchAt, len("<title"))
				s.headAt = keepOverlap(s.buf, s.headAt, len("</head>"))
				return "", false
			}
			open := bytes.IndexByte(s.buf[idx:], '>')
			if open < 0 {
				s.searchAt = idx
				return "", false
			}
			s.inBody = true
			s.bodyStart = idx + open + 1
			s.searchAt = s.bodyStart
			continue
		}

		end := indexFoldASCIIFrom(s.buf, "</title>", s.searchAt)
		if end < 0 {
			s.searchAt = keepOverlap(s.buf, s.bodyStart, len("</title>"))
			return "", false
		}
		return strings.Join(strings.Fields(string(s.buf[s.bodyStart:end])), " "), true
	}
}

// keepOverlap moves the search cursor forward but leaves (needleLen-1) bytes of
// the buffer to be re-examined, so a needle split across reads is not missed.
func keepOverlap(data []byte, from, needleLen int) int {
	next := len(data) - (needleLen - 1)
	if next < from {
		return from
	}
	return next
}

// titleFromBuffer reports the title and whether the scan can stop: found the
// closing tag, or the document head ended without a title.
func titleFromBuffer(data []byte) (string, bool) {
	s := titleScan{buf: data}
	return s.scan()
}

// indexFoldASCII searches for a lowercase ASCII needle without changing the
// byte offsets of the haystack. Lowercasing the whole buffer is wrong: Unicode
// case mapping can change byte lengths, which shifts every index after it.
func indexFoldASCII(data []byte, needle string) int {
	return indexFoldASCIIFrom(data, needle, 0)
}

// indexFoldASCIIFrom is indexFoldASCII starting at offset from.
func indexFoldASCIIFrom(data []byte, needle string, from int) int {
	if needle == "" || len(data) < len(needle) {
		return -1
	}
	if from < 0 {
		from = 0
	}
	for i := from; i+len(needle) <= len(data); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			c := data[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// sameURL reports whether two URLs point at the same site for display purposes.
// Only the host is compared: a redirect that stays on the same host (for example
// / -> /Security/Login) is not interesting during triage and would add noise to
// every line, so the probed URL stays the visible one.
func sameURL(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return a == b
	}
	ub, err := url.Parse(b)
	if err != nil {
		return a == b
	}
	return strings.EqualFold(strings.TrimSuffix(ua.Hostname(), "."), strings.TrimSuffix(ub.Hostname(), "."))
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 180 {
		return msg[:180]
	}
	return msg
}

func writeResults(w io.Writer, results []result, cfg config) error {
	for _, res := range results {
		if err := writeResult(w, res, cfg); err != nil {
			return err
		}
	}
	return nil
}

// writeResult applies the output filters and writes one result. Both the sorted
// and the streaming (-no-sort) paths go through it so their output matches.
func writeResult(w io.Writer, res result, cfg config) error {
	if cfg.filterWildcard && res.Wildcard {
		return nil
	}
	if !res.Live && !cfg.jsonOut {
		return nil
	}

	if cfg.jsonOut {
		return json.NewEncoder(w).Encode(res)
	}

	if cfg.quiet {
		value := resultURL(res)
		if cfg.noScheme {
			value = stripScheme(value)
		}
		_, err := fmt.Fprintln(w, value)
		return err
	}

	switch cfg.mode {
	case "dns":
		_, err := fmt.Fprintln(w, formatDNSResult(res, cfg))
		return err
	default:
		_, err := fmt.Fprintln(w, formatHTTPResult(res, cfg))
		return err
	}
}

// isBrokenPipe lets "palm | head" exit cleanly instead of reporting the
// consumer's early close as a scan failure.
func isBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "broken pipe") || strings.Contains(msg, "pipe is being closed")
}

func resultURL(res result) string {
	if res.ProbedURL != "" {
		return res.ProbedURL
	}
	if res.URL != "" {
		return res.URL
	}
	return res.Host
}

// stripScheme removes a leading http:// or https:// so text output can match the
// bare host form that other recon tools emit.
func stripScheme(value string) string {
	if rest, ok := strings.CutPrefix(value, "https://"); ok {
		return rest
	}
	if rest, ok := strings.CutPrefix(value, "http://"); ok {
		return rest
	}
	return value
}

func formatDNSResult(res result, cfg config) string {
	value := res.Host
	var parts []string
	if cfg.status && len(res.IPs) > 0 {
		parts = append(parts, strings.Join(res.IPs, ","))
	}
	if res.Wildcard {
		parts = append(parts, "wildcard")
	}
	if res.Takeover {
		parts = append(parts, "takeover="+res.Provider)
	}
	if res.CNAME != "" {
		parts = append(parts, "cname="+res.CNAME)
	}
	if len(parts) == 0 {
		return value
	}
	return fmt.Sprintf("%s [%s]", value, strings.Join(parts, " | "))
}

func formatHTTPResult(res result, cfg config) string {
	value := res.ProbedURL
	if value == "" {
		value = res.URL
	}
	if value == "" {
		value = res.Host
	}
	if cfg.noScheme {
		value = stripScheme(value)
	}
	var parts []string
	if cfg.status && res.StatusCode > 0 {
		parts = append(parts, strconv.Itoa(res.StatusCode))
	}
	if cfg.status && len(res.IPs) > 0 {
		parts = append(parts, "ip="+strings.Join(res.IPs, ","))
	}
	if res.URL != "" && res.ProbedURL != "" && !sameURL(res.ProbedURL, res.URL) {
		final := res.URL
		if cfg.noScheme {
			final = stripScheme(final)
		}
		parts = append(parts, "final="+final)
	}
	if cfg.title && res.Title != "" {
		parts = append(parts, "title="+res.Title)
	}
	if cfg.server && res.Server != "" {
		parts = append(parts, "server="+res.Server)
	}
	if cfg.contentLen && res.Length != nil {
		parts = append(parts, "cl="+strconv.FormatInt(*res.Length, 10))
	}
	if cfg.responseTime && res.ResponseTimeMS != nil {
		parts = append(parts, "rt="+strconv.FormatInt(*res.ResponseTimeMS, 10)+"ms")
	}
	if cfg.location && res.Location != "" {
		parts = append(parts, "location="+res.Location)
	}
	if cfg.tlsInfo && res.TLSIssuer != "" {
		detail := res.TLSIssuer
		if res.TLSDaysLeft != nil {
			if *res.TLSDaysLeft < 0 {
				detail += " expired"
			} else {
				detail += fmt.Sprintf(" %dd", *res.TLSDaysLeft)
			}
		}
		parts = append(parts, "tls="+detail)
	}
	if cfg.tlsInfo && res.TLSMismatch {
		parts = append(parts, "tls_mismatch")
	}
	if res.Wildcard {
		parts = append(parts, "wildcard")
	}
	if res.Takeover {
		parts = append(parts, "takeover="+res.Provider)
	}
	if res.CNAME != "" {
		parts = append(parts, "cname="+res.CNAME)
	}
	if len(parts) == 0 {
		return value
	}
	return fmt.Sprintf("%s [%s]", value, strings.Join(parts, " | "))
}
