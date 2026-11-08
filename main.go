package main

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const version = "0.5.0"
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
	TagName string `json:"tag_name"`
	URL     string `json:"html_url"`
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
func (w *wildcardCache) matches(ips []string, host string) bool {
	if w == nil || len(ips) == 0 {
		return false
	}
	parent := parentDomain(host)
	if parent == "" {
		return false
	}
	e := w.entry(parent)
	e.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
		defer cancel()
		random := randomLabel() + "." + parent
		if resolved, err := lookupHostWithCtx(ctx, random, w.pool); err == nil {
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
// and aaa.bbb.example.co.uk -> example.co.uk.
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
	return strings.Join(labels[len(labels)-keep:], ".")
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
	{Provider: "github-pages", CNAMEs: []string{"github.io"}, Bodies: []string{"there isn't a github pages site here", "github pages"}},
	{Provider: "heroku", CNAMEs: []string{"herokuapp.com", "herokudns.com"}, Bodies: []string{"no such app", "heroku | no such app"}},
	{Provider: "netlify", CNAMEs: []string{"netlify.app", "netlifyglobalcdn.com"}, Bodies: []string{"not found - request id", "netlify"}},
	{Provider: "vercel", CNAMEs: []string{"vercel-dns.com", "vercel.app"}, Bodies: []string{"the deployment could not be found", "vercel"}},
	{Provider: "azure", CNAMEs: []string{"azurewebsites.net", "cloudapp.net", "trafficmanager.net"}, Bodies: []string{"404 web site not found", "azure"}},
	{Provider: "fastly", CNAMEs: []string{"fastly.net"}, Bodies: []string{"fastly error: unknown domain"}},
	{Provider: "shopify", CNAMEs: []string{"myshopify.com"}, Bodies: []string{"sorry, this shop is currently unavailable"}},
	{Provider: "zendesk", CNAMEs: []string{"zendesk.com"}, Bodies: []string{"help center closed", "oops, this help center no longer exists"}},
	{Provider: "readme", CNAMEs: []string{"readme.io"}, Bodies: []string{"project doesnt exist", "project doesn't exist"}},
}

func main() {
	// Go's HTTP transport can log noisy "Unsolicited response received on idle
	// HTTP channel" lines to stderr. palm has no logging of its own, so keep the
	// stream clean for pipelines.
	log.SetOutput(io.Discard)

	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	if cfg.inputFile == "" && stdinIsTerminal() {
		fmt.Fprint(os.Stdout, usage())
		return
	}

	hosts, err := readHosts(cfg.inputFile, os.Stdin)
	if err != nil {
		fatal(err)
	}
	if len(hosts) == 0 {
		return
	}

	out, closeOut, err := outputWriter(cfg.outputFile)
	if err != nil {
		fatal(err)
	}
	defer closeOut()

	results, err := runChecks(hosts, cfg)
	if err != nil {
		fatal(err)
	}
	writeResults(out, results, cfg)
}

func parseFlags(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("palm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.inputFile, "l", "", "subdomain list file")
	fs.StringVar(&cfg.inputFile, "list", "", "subdomain list file")
	fs.StringVar(&cfg.outputFile, "o", "", "output file")
	fs.StringVar(&cfg.mode, "mode", "both", "check mode: dns, http, both")
	fs.StringVar(&cfg.resolverFile, "r", "", "resolver file for DNS lookups")
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
	showHelp := fs.Bool("h", false, "show help")
	showVersion := fs.Bool("version", false, "show version")
	checkUpdate := fs.Bool("check-update", false, "check latest GitHub release")
	runUpdate := fs.Bool("update", false, "update palm with go install")
	showTools := fs.Bool("tools", false, "show common tool pipelines")
	showMiami := fs.Bool("miami", false, "show the Miami easter egg")

	if err := fs.Parse(reorderArgs(args)); err != nil {
		return cfg, usageError()
	}
	if *showHelp {
		fmt.Fprint(os.Stdout, usage())
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
		fmt.Fprint(os.Stdout, localizedToolsUsage())
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
	return cfg, nil
}

func reorderArgs(args []string) []string {
	valueFlags := map[string]struct{}{
		"-l": {}, "-list": {}, "-o": {}, "-mode": {}, "-r": {}, "-c": {}, "-timeout": {}, "-mc": {}, "-fc": {}, "-method": {}, "-H": {},
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
	if _, err := exec.LookPath("go"); err != nil {
		return errors.New("go command not found; install Go or download a binary from the GitHub releases page")
	}
	fmt.Fprintf(stdout, "updating palm with: go install %s@latest\n", modulePath)
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

func usageError() error {
	return errors.New(strings.TrimSpace(usage()))
}

func usage() string {
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
  -r string          resolver file for DNS lookups
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
  -tools             show common tool pipelines
  -check-update      check latest GitHub release
  -update            update palm with go install
  -version           show version
  -h                 show help
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
  -r string          DNS sorgulari icin resolver dosyasi
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
  -tools             yaygin araclarla ornek pipeline goster
  -check-update      en son GitHub release surumunu kontrol et
  -update            go install ile palm'i guncelle
  -version           surumu goster
  -h                 yardimi goster
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
	if isTurkishLocale() {
		return `palm ile yaygin arac ornekleri:

  subfinder -d example.com -silent | palm
  assetfinder --subs-only example.com | palm
  amass enum -passive -d example.com | palm
  findomain -t example.com -q | palm
  chaos -d example.com -silent | palm

Not: palm stdin'den okur, txt dosyasi da kabul eder: palm subs.txt
`
	}
	return toolsUsage()
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

func outputWriter(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func runChecks(hosts []string, cfg config) ([]result, error) {
	resolvers, err := loadResolverPool(cfg.resolverFile)
	if err != nil {
		return nil, err
	}
	jobs := make(chan string)
	results := make(chan result)

	var wildcards *wildcardCache
	if cfg.wildcard || cfg.filterWildcard {
		wildcards = newWildcardCache(resolvers, cfg.timeout)
	}

	client := &http.Client{
		Timeout: cfg.timeout,
		Transport: &http.Transport{
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
		},
	}
	if !cfg.followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				results <- checkHost(host, cfg, client, resolvers, wildcards)
			}
		}()
	}

	go func() {
		for _, host := range hosts {
			jobs <- host
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	return collectResults(results), nil
}

func collectResults(results <-chan result) []result {
	out := make([]result, 0)
	for res := range results {
		out = append(out, res)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Host < out[j].Host
	})
	return out
}

func checkHost(host string, cfg config, client *http.Client, resolvers *resolverPool, wildcards *wildcardCache) result {
	res := result{Host: host}

	if cfg.mode == "dns" || cfg.mode == "both" {
		ips, err := lookupHost(host, cfg.timeout, resolvers)
		if err == nil && len(ips) > 0 {
			res.DNS = true
			res.IPs = ips
			res.Live = true
			if wildcards != nil && wildcards.matches(ips, host) {
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
		ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
		probe, err := checkHTTP(ctx, host, cfg, client)
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
		takeover, provider, cname := detectTakeover(host, cfg.timeout, resolvers, client)
		res.CNAME = cname
		res.Takeover = takeover
		res.Provider = provider
		if takeover {
			res.Live = true
		}
	}

	return res
}

func lookupHost(host string, timeout time.Duration, resolvers *resolverPool) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return lookupHostWithCtx(ctx, host, resolvers)
}

func lookupHostWithCtx(ctx context.Context, host string, resolvers *resolverPool) ([]string, error) {
	ips, err := resolvers.lookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	sort.Strings(ips)
	return ips, nil
}

func detectTakeover(host string, timeout time.Duration, resolvers *resolverPool, client *http.Client) (bool, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cname, err := lookupCNAME(ctx, host, resolvers)
	if err != nil || cname == "" {
		return false, "", ""
	}
	return evaluateTakeover(host, cname, client)
}

// evaluateTakeover keeps the resolved CNAME even when no takeover fingerprint
// matches, so `-takeover -json` still shows the CNAME chain for manual review.
func evaluateTakeover(host, cname string, client *http.Client) (bool, string, string) {
	fingerprint, ok := matchTakeoverCNAME(cname)
	if !ok {
		return false, "", cname
	}

	body := fetchTakeoverBody(host, client)
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
			if strings.Contains(cname, strings.ToLower(pattern)) {
				return fp, true
			}
		}
	}
	return takeoverFingerprint{}, false
}

func fetchTakeoverBody(host string, client *http.Client) string {
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequest(http.MethodGet, scheme+"://"+host, nil)
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

// schemePreferenceGrace is how long an HTTP result waits for a still-pending
// HTTPS attempt before it is returned. It keeps HTTPS preferred without paying
// a full timeout for HTTP-only hosts.
const schemePreferenceGrace = 250 * time.Millisecond

func checkHTTP(ctx context.Context, host string, cfg config, client *http.Client) (httpProbe, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		probe  httpProbe
		err    error
		scheme string
	}

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
	var grace <-chan time.Time
	for i := 0; i < 2; i++ {
		var out outcome
		if grace != nil {
			select {
			case out = <-ch:
			case <-grace:
				// HTTP already answered and HTTPS is still not done.
				return httpOK.probe, nil
			}
		} else {
			out = <-ch
		}

		if out.err == nil && statusAllowed(out.probe.StatusCode, cfg) {
			if out.scheme == "https" {
				return out.probe, nil
			}
			httpCopy := out
			httpOK = &httpCopy
			grace = time.After(schemePreferenceGrace)
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
	buf := make([]byte, 0, 8192)
	chunk := make([]byte, 8192)
	for len(buf) < titleReadLimit {
		n, err := r.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if title, done := titleFromBuffer(buf); done {
				return title
			}
		}
		if err != nil {
			break
		}
	}
	title, _ := titleFromBuffer(buf)
	return title
}

// titleFromBuffer reports the title and whether the scan can stop: found the
// closing tag, or the document head ended without a title.
func titleFromBuffer(data []byte) (string, bool) {
	lower := strings.ToLower(string(data))
	start := strings.Index(lower, "<title")
	if start < 0 {
		return "", strings.Contains(lower, "</head>")
	}
	open := strings.IndexByte(lower[start:], '>')
	if open < 0 {
		return "", false
	}
	body := start + open + 1
	end := strings.Index(lower[body:], "</title>")
	if end < 0 {
		return "", strings.Contains(lower[body:], "</head>")
	}
	return strings.Join(strings.Fields(string(data[body:body+end])), " "), true
}

func sameURL(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return a == b
	}
	ub, err := url.Parse(b)
	if err != nil {
		return a == b
	}
	if !strings.EqualFold(ua.Host, ub.Host) || ua.RawQuery != ub.RawQuery {
		return false
	}
	return strings.TrimSuffix(ua.Path, "/") == strings.TrimSuffix(ub.Path, "/")
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

func writeResults(w io.Writer, results []result, cfg config) {
	enc := json.NewEncoder(w)
	for _, res := range results {
		if cfg.filterWildcard && res.Wildcard {
			continue
		}
		if cfg.quiet && !res.Live {
			continue
		}
		if !cfg.jsonOut && !res.Live {
			continue
		}

		if cfg.jsonOut {
			_ = enc.Encode(res)
			continue
		}

		if cfg.quiet {
			fmt.Fprintln(w, resultURL(res))
			continue
		}

		switch cfg.mode {
		case "dns":
			fmt.Fprintln(w, formatDNSResult(res, cfg))
		default:
			fmt.Fprintln(w, formatHTTPResult(res, cfg))
		}
	}
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
	var parts []string
	if cfg.status && res.StatusCode > 0 {
		parts = append(parts, strconv.Itoa(res.StatusCode))
	}
	if cfg.status && len(res.IPs) > 0 {
		parts = append(parts, "ip="+strings.Join(res.IPs, ","))
	}
	if res.URL != "" && res.ProbedURL != "" && !sameURL(res.ProbedURL, res.URL) {
		parts = append(parts, "final="+res.URL)
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
