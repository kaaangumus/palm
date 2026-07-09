package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const version = "0.1.0"

type config struct {
	inputFile    string
	outputFile   string
	mode         string
	concurrency  int
	timeout      time.Duration
	resolverFile string
	jsonOut      bool
	status       bool
	title        bool
	server       bool
	contentLen   bool
	takeover     bool
	quiet        bool
	matchCodes   map[int]struct{}
	filterCodes  map[int]struct{}
}

type result struct {
	Host       string   `json:"host"`
	Live       bool     `json:"live"`
	DNS        bool     `json:"dns"`
	IPs        []string `json:"ips,omitempty"`
	URL        string   `json:"url,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	Title      string   `json:"title,omitempty"`
	Server     string   `json:"server,omitempty"`
	Length     *int64   `json:"content_length,omitempty"`
	Takeover   bool     `json:"takeover,omitempty"`
	Provider   string   `json:"takeover_provider,omitempty"`
	CNAME      string   `json:"cname,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type httpProbe struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	Length     *int64
}

type resolverPool struct {
	addrs []string
	next  uint64
}

type takeoverFingerprint struct {
	Provider string
	CNAMEs   []string
	Bodies   []string
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

	results := runChecks(hosts, cfg)
	writeResults(out, results, cfg)
}

func parseFlags(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("palm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.inputFile, "l", "", "subdomain list file")
	fs.StringVar(&cfg.inputFile, "list", "", "subdomain list file")
	fs.StringVar(&cfg.outputFile, "o", "", "output file")
	fs.StringVar(&cfg.mode, "mode", "http", "check mode: dns, http, both")
	fs.StringVar(&cfg.resolverFile, "r", "", "resolver file for DNS lookups")
	fs.IntVar(&cfg.concurrency, "c", 100, "concurrent workers")
	timeout := fs.Int("timeout", 5, "timeout in seconds")
	matchCodes := fs.String("mc", "", "match HTTP status codes")
	filterCodes := fs.String("fc", "", "filter HTTP status codes")
	fs.BoolVar(&cfg.jsonOut, "json", false, "write JSON lines")
	fs.BoolVar(&cfg.status, "status", false, "include HTTP status in text output")
	fs.BoolVar(&cfg.title, "title", false, "include page title")
	fs.BoolVar(&cfg.server, "server", false, "include server header")
	fs.BoolVar(&cfg.contentLen, "cl", false, "include content length")
	fs.BoolVar(&cfg.takeover, "takeover", false, "check subdomain takeover fingerprints")
	fs.BoolVar(&cfg.quiet, "q", false, "only print live hosts/URLs")
	showHelp := fs.Bool("h", false, "show help")
	showVersion := fs.Bool("version", false, "show version")
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
		"-l": {}, "-list": {}, "-o": {}, "-mode": {}, "-r": {}, "-c": {}, "-timeout": {}, "-mc": {}, "-fc": {},
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

func usageError() error {
	return errors.New(strings.TrimSpace(usage()))
}

func usage() string {
	if isTurkishLocale() {
		return trUsageClean()
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
  -mode string       dns, http, both (default "http")
  -r string          resolver file for DNS lookups
  -c int             concurrent workers (default 100)
  -timeout int       timeout in seconds (default 5)
  -mc string         match HTTP status codes, comma-separated
  -fc string         filter HTTP status codes, comma-separated
  -json              write JSON lines
  -status            include HTTP status in text output
  -title             include page title
  -server            include server header
  -cl                include content length
  -takeover          check subdomain takeover fingerprints
  -q                 only print live hosts/URLs
  -tools             show common tool pipelines
  -version           show version
  -h                 show help
`
}

func trUsage() string {
	return `palm - hızlı subdomain live checker

Kullanım:
  subfinder -d example.com -silent | palm
  palm subs.txt
  dnsx -l subs.txt -silent | palm -mode http -status
  palm -l subs.txt -mode both -json -o live.jsonl

Parametreler:
  -l, -list string   subdomain liste dosyası
  -o string          çıktı dosyası
  -mode string       kontrol modu: dns, http, both (varsayılan "http")
  -c int             eşzamanlı worker sayısı (varsayılan 100)
  -timeout int       saniye cinsinden timeout (varsayılan 5)
  -json              JSON lines formatında yaz
  -status            text çıktıda HTTP status veya DNS IP bilgisini göster
  -q                 sadece live host/URL yaz
  -tools             yaygın araçlarla örnek pipeline göster
  -version           sürümü göster
  -h                 yardımı göster
`
}

func trUsageClean() string {
	return `palm - hızlı subdomain live checker

Kullanım:
  subfinder -d example.com -silent | palm
  palm subs.txt
  dnsx -l subs.txt -silent | palm -mode http -status
  palm subs.txt -mc 200,301,302 -title -server
  palm -l subs.txt -mode both -json -o live.jsonl

Parametreler:
  -l, -list string   subdomain liste dosyası
  -o string          çıktı dosyası
  -mode string       kontrol modu: dns, http, both (varsayılan "http")
  -r string          DNS sorguları için resolver dosyası
  -c int             eşzamanlı worker sayısı (varsayılan 100)
  -timeout int       saniye cinsinden timeout (varsayılan 5)
  -mc string         eşleşecek HTTP status kodları, virgülle ayrılır
  -fc string         filtrelenecek HTTP status kodları, virgülle ayrılır
  -json              JSON lines formatında yaz
  -status            text çıktıda HTTP status veya DNS IP bilgisini göster
  -title             sayfa başlığını göster
  -server            server header bilgisini göster
  -cl                content length bilgisini göster
  -q                 sadece live host/URL yaz
  -tools             yaygın araçlarla örnek pipeline göster
  -version           sürümü göster
  -h                 yardımı göster
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
		return `palm ile yaygın araç örnekleri:

  subfinder -d example.com -silent | palm
  assetfinder --subs-only example.com | palm
  amass enum -passive -d example.com | palm
  findomain -t example.com -q | palm
  chaos -d example.com -silent | palm

Not: palm stdin'den okur, txt dosyası da kabul eder: palm subs.txt
`
	}
	return toolsUsage()
}

func toolsUsage() string {
	if isTurkishLocale() {
		return `palm ile yaygın araç örnekleri:

  subfinder -d example.com -silent | palm
  assetfinder --subs-only example.com | palm
  amass enum -passive -d example.com | palm
  findomain -t example.com -q | palm
  chaos -d example.com -silent | palm

Not: palm stdin'den okur, txt dosyası da kabul eder: palm subs.txt
`
	}
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
        Easter egg: Kaan Gümüş
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
	raw := strings.Trim(fields[0], " ,;[](){}\"'")
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

func runChecks(hosts []string, cfg config) []result {
	resolvers, err := loadResolverPool(cfg.resolverFile)
	if err != nil {
		return []result{{Error: err.Error()}}
	}
	jobs := make(chan string)
	results := make(chan result)

	client := &http.Client{
		Timeout: cfg.timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        cfg.concurrency * 2,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				results <- checkHost(host, cfg, client, resolvers)
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

	return collectResults(results)
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

func checkHost(host string, cfg config, client *http.Client, resolvers *resolverPool) result {
	res := result{Host: host}

	if cfg.mode == "dns" || cfg.mode == "both" {
		ips, err := lookupHost(host, cfg.timeout, resolvers)
		if err == nil && len(ips) > 0 {
			res.DNS = true
			res.IPs = ips
			res.Live = true
		} else if cfg.mode == "dns" {
			res.Error = shortErr(err)
			return res
		}
	}

	if cfg.mode == "http" || cfg.mode == "both" {
		if cfg.mode == "both" && !res.DNS {
			res.Live = false
			return res
		}
		probe, err := checkHTTP(host, cfg, client)
		if err == nil {
			res.Live = true
			res.URL = probe.URL
			res.StatusCode = probe.StatusCode
			res.Title = probe.Title
			res.Server = probe.Server
			res.Length = probe.Length
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
	fingerprint, ok := matchTakeoverCNAME(cname)
	if !ok {
		return false, "", ""
	}

	body := fetchTakeoverBody(host, client)
	if body == "" {
		return false, "", ""
	}
	if matchTakeoverBody(body, fingerprint) {
		return true, fingerprint.Provider, cname
	}
	return false, "", ""
}

func lookupCNAME(ctx context.Context, host string, resolvers *resolverPool) (string, error) {
	if resolvers == nil || len(resolvers.addrs) == 0 {
		return net.DefaultResolver.LookupCNAME(ctx, host)
	}
	idx := atomic.AddUint64(&resolvers.next, 1)
	addr := resolvers.addrs[int(idx-1)%len(resolvers.addrs)]
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "udp", addr)
		},
	}
	return resolver.LookupCNAME(ctx, host)
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
	return &resolverPool{addrs: addrs}, nil
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
	if p == nil || len(p.addrs) == 0 {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	idx := atomic.AddUint64(&p.next, 1)
	addr := p.addrs[int(idx-1)%len(p.addrs)]
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "udp", addr)
		},
	}
	return resolver.LookupHost(ctx, host)
}

func checkHTTP(host string, cfg config, client *http.Client) (httpProbe, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		target := scheme + "://" + host
		probe, err := requestURL(target, cfg, client)
		if err == nil && statusAllowed(probe.StatusCode, cfg) {
			return probe, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("status %d did not match filters", probe.StatusCode)
		}
	}
	return httpProbe{}, lastErr
}

func requestURL(target string, cfg config, client *http.Client) (httpProbe, error) {
	method := http.MethodHead
	if cfg.title {
		method = http.MethodGet
	}
	probe, err := doRequest(target, method, cfg, client)
	if err != nil {
		return httpProbe{}, err
	}
	if method == http.MethodHead && (probe.StatusCode == http.StatusMethodNotAllowed || probe.StatusCode == http.StatusForbidden) {
		return doRequest(target, http.MethodGet, cfg, client)
	}
	return probe, nil
}

func doRequest(target, method string, cfg config, client *http.Client) (httpProbe, error) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return httpProbe{}, err
	}
	req.Header.Set("User-Agent", "palm/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return httpProbe{}, err
	}
	defer resp.Body.Close()

	probe := httpProbe{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
	}
	if cfg.contentLen && resp.ContentLength >= 0 {
		length := resp.ContentLength
		probe.Length = &length
	}
	if cfg.server {
		probe.Server = resp.Header.Get("Server")
	}
	if cfg.title && method == http.MethodGet {
		probe.Title = readTitle(resp.Body)
	}
	return probe, nil
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

func readTitle(r io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(r, 512*1024))
	if err != nil {
		return ""
	}
	lower := strings.ToLower(string(data))
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(lower[start:], ">")
	if start < 0 {
		return ""
	}
	start += strings.Index(lower, "<title")
	end := strings.Index(lower[start+1:], "</title>")
	if end < 0 {
		return ""
	}
	title := string(data[start+1 : start+1+end])
	return strings.Join(strings.Fields(title), " ")
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

		switch cfg.mode {
		case "dns":
			fmt.Fprintln(w, formatDNSResult(res, cfg))
		default:
			fmt.Fprintln(w, formatHTTPResult(res, cfg))
		}
	}
}

func formatDNSResult(res result, cfg config) string {
	value := res.Host
	var parts []string
	if cfg.status && len(res.IPs) > 0 {
		parts = append(parts, strings.Join(res.IPs, ","))
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
	value := res.URL
	if value == "" {
		value = res.Host
	}
	var parts []string
	if cfg.status && res.StatusCode > 0 {
		parts = append(parts, strconv.Itoa(res.StatusCode))
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
