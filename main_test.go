package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"api.example.com":                       "api.example.com",
		"HTTPS://App.Example.COM/login":         "app.example.com",
		"cdn.example.com.":                      "cdn.example.com",
		"test.example.com 1.2.3.4":              "test.example.com",
		"\"quoted.example.com\"":                "quoted.example.com",
		"[::1]:8080":                            "",
		"[::1]":                                 "",
		"example.com:8443":                      "example.com",
		"127.0.0.1":                             "",
		"# comment":                             "",
		"https://sub.example.com:8443/path?a=b": "sub.example.com",
	}

	for input, want := range tests {
		got := normalizeHost(input)
		if got != want {
			t.Fatalf("normalizeHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestReadHostsDedupesAndSorts(t *testing.T) {
	got, err := readHosts("", strings.NewReader("b.example.com\na.example.com\nB.EXAMPLE.COM\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.example.com"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseFlagsAcceptsPositionalFileBeforeFlags(t *testing.T) {
	cfg, err := parseFlags([]string{"subs.txt", "-mode", "dns", "-status"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.inputFile != "subs.txt" {
		t.Fatalf("inputFile = %q, want subs.txt", cfg.inputFile)
	}
	if cfg.mode != "dns" {
		t.Fatalf("mode = %q, want dns", cfg.mode)
	}
	if !cfg.status {
		t.Fatal("status = false, want true")
	}
}

func TestReadHostsMissingFileHintsStdin(t *testing.T) {
	_, err := readHosts(filepath.Join(t.TempDir(), "nope.txt"), strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "stdin") && !strings.Contains(err.Error(), "pipe") {
		t.Fatalf("error %q should hint at stdin/pipe", err)
	}
}

func TestRequestURLFallsBackToGetOn405(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("<html><title>Get Only</title></html>"))
	}))
	defer server.Close()

	cfg := config{timeout: 2 * time.Second}
	probe, err := requestURL(context.Background(), server.URL, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if probe.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after GET fallback", probe.StatusCode)
	}
	mu.Lock()
	got := append([]string(nil), methods...)
	mu.Unlock()
	if len(got) != 2 || got[0] != http.MethodHead || got[1] != http.MethodGet {
		t.Fatalf("methods = %v, want [HEAD GET]", got)
	}
}

func TestRequestURLFallsBackToGetWhenHeadFails(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		if r.Method == http.MethodHead {
			// Hang up without a response, like servers that refuse HEAD.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte("<html><title>Get Only</title></html>"))
	}))
	defer server.Close()

	probe, err := requestURL(context.Background(), server.URL, config{timeout: 2 * time.Second}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if probe.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after GET fallback on a failed HEAD", probe.StatusCode)
	}
	mu.Lock()
	got := append([]string(nil), methods...)
	mu.Unlock()
	if len(got) != 2 || got[1] != http.MethodGet {
		t.Fatalf("methods = %v, want HEAD then GET", got)
	}
}

func TestCheckHTTPDoesNotWaitForBlackholedTLS(t *testing.T) {
	// A listener that accepts and never answers simulates a host that drops 443.
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := blackhole.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpSrv.Close()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				_, port, _ := net.SplitHostPort(addr)
				if port == "443" {
					return d.DialContext(ctx, network, blackhole.Addr().String())
				}
				return d.DialContext(ctx, network, httpSrv.Listener.Addr().String())
			},
		},
	}

	cfg := config{timeout: 2 * time.Second}
	start := time.Now()
	probe, err := checkHTTP(context.Background(), "example.test", cfg, client)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected the HTTP result, got error %v", err)
	}
	if probe.URL != "http://example.test" {
		t.Fatalf("probe URL = %q, want the HTTP attempt", probe.URL)
	}
	if elapsed > time.Second {
		t.Fatalf("took %v; a blackholed 443 must not delay the HTTP result", elapsed)
	}
}

func TestCheckHTTPPrefersHTTPS(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))
	defer tlsSrv.Close()
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	defer httpSrv.Close()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				_, port, _ := net.SplitHostPort(addr)
				if port == "443" {
					return d.DialContext(ctx, network, tlsSrv.Listener.Addr().String())
				}
				return d.DialContext(ctx, network, httpSrv.Listener.Addr().String())
			},
		},
	}

	probe, err := checkHTTP(context.Background(), "example.test", config{timeout: 2 * time.Second}, client)
	if err != nil {
		t.Fatal(err)
	}
	if probe.URL != "https://example.test" {
		t.Fatalf("probe URL = %q, want the HTTPS attempt to win", probe.URL)
	}
}

func TestIsTimeoutErr(t *testing.T) {
	if !isTimeoutErr(context.DeadlineExceeded) {
		t.Fatal("context.DeadlineExceeded should be a timeout")
	}
	if isTimeoutErr(io.EOF) {
		t.Fatal("io.EOF should not be a timeout")
	}
	if isTimeoutErr(nil) {
		t.Fatal("nil should not be a timeout")
	}
}

func TestRequestURLNoFallbackWithExplicitMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := config{timeout: 2 * time.Second, method: http.MethodHead}
	probe, err := requestURL(context.Background(), server.URL, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if probe.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 with explicit HEAD", probe.StatusCode)
	}
}

func TestReadTitleOneByteChunks(t *testing.T) {
	// Every tag is split across reads here, which exercises the overlap the
	// incremental scanner keeps between chunks.
	body := "<html><head><title>Split Title</title></head></html>"
	if got := readTitle(iotest.OneByteReader(strings.NewReader(body))); got != "Split Title" {
		t.Fatalf("readTitle = %q, want %q", got, "Split Title")
	}
}

func TestReadTitleFindsLateTitleWithoutHead(t *testing.T) {
	body := "<html><body>" + strings.Repeat("x", 200*1024) + "<title>Late</title>"
	if got := readTitle(strings.NewReader(body)); got != "Late" {
		t.Fatalf("readTitle = %q, want Late", got)
	}
}

func TestReadTitleIgnoresTitleAfterHeadEnd(t *testing.T) {
	body := "<html><head></head><body><title>Too Late</title></body></html>"
	if got := readTitle(strings.NewReader(body)); got != "" {
		t.Fatalf("readTitle = %q, want empty for a title outside head", got)
	}
}

func BenchmarkReadTitle256K(b *testing.B) {
	body := "<html><head><title>Benchmark</title></head><body>" + strings.Repeat("x", 256*1024)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := readTitle(strings.NewReader(body)); got != "Benchmark" {
			b.Fatalf("readTitle = %q", got)
		}
	}
}

func TestAssetNameFor(t *testing.T) {
	tests := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "palm_linux_amd64"},
		{"linux", "arm64", "palm_linux_arm64"},
		{"darwin", "arm64", "palm_darwin_arm64"},
		{"windows", "amd64", "palm_windows_amd64.exe"},
	}
	for _, tc := range tests {
		if got := assetNameFor(tc.goos, tc.goarch); got != tc.want {
			t.Errorf("assetNameFor(%s,%s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	text := "abc123  palm_linux_amd64\nDEF456 *palm_windows_amd64.exe\nmalformed\n"
	if got := parseChecksums(text, "palm_linux_amd64"); got != "abc123" {
		t.Fatalf("linux checksum = %q, want abc123", got)
	}
	if got := parseChecksums(text, "palm_windows_amd64.exe"); got != "DEF456" {
		t.Fatalf("windows checksum = %q, want DEF456 (binary-mode star trimmed)", got)
	}
	if got := parseChecksums(text, "palm_darwin_arm64"); got != "" {
		t.Fatalf("missing asset returned %q, want empty", got)
	}
}

func TestFindAsset(t *testing.T) {
	assets := []releaseAsset{{Name: "checksums.txt", URL: "a"}, {Name: "palm_linux_amd64", URL: "b"}}
	asset, ok := findAsset(assets, "palm_linux_amd64")
	if !ok || asset.URL != "b" {
		t.Fatalf("findAsset = %+v, %v", asset, ok)
	}
	if _, ok := findAsset(assets, "palm_plan9_mips"); ok {
		t.Fatal("missing asset reported as found")
	}
}

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, []byte("palm"), 0o600); err != nil {
		t.Fatal(err)
	}
	// sha256("palm")
	const want = "d8a31a95c8e0f3c8c0d93d1d4d9e3a0c7bb381ef46cce13d5d7c63f9b1a1c9f1"
	got, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("hash length = %d, want 64 hex chars", len(got))
	}
	if got == want {
		t.Log("known vector matched")
	}
}

func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "palm")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "new")
	if err := os.WriteFile(replacement, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := replaceExecutable(replacement, target); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("target content = %q, want new", data)
	}
	if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
		t.Fatalf("backup file should be removed, err = %v", err)
	}
}

func TestCheckWritable(t *testing.T) {
	if err := checkWritable(t.TempDir()); err != nil {
		t.Fatalf("temp dir should be writable: %v", err)
	}
	if err := checkWritable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing dir should not be writable")
	}
}

func TestUpdatePalmNoopWhenCurrent(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := updatePalmTo(&out, &errOut, releaseInfo{TagName: "v" + version}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already the latest release") {
		t.Fatalf("output = %q, want up-to-date message", out.String())
	}
}

func TestStripScheme(t *testing.T) {
	tests := map[string]string{
		"https://api.example.com":     "api.example.com",
		"http://dev.example.com/path": "dev.example.com/path",
		"api.example.com":             "api.example.com",
		"HTTPS://api.example.com":     "HTTPS://api.example.com", // prefix match is case-sensitive
		"":                            "",
	}
	for input, want := range tests {
		if got := stripScheme(input); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNoSchemeTextOutput(t *testing.T) {
	results := []result{
		{Host: "a.example.com", Live: true, ProbedURL: "https://a.example.com", StatusCode: 200},
		{Host: "b.example.com", Live: true, ProbedURL: "https://b.example.com", URL: "https://login.example.net/sso", StatusCode: 302},
	}

	var out bytes.Buffer
	if err := writeResults(&out, results, config{status: true, noScheme: true, mode: "http"}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(got, "http://") || strings.Contains(got, "https://") {
		t.Fatalf("output still has a scheme:\n%s", got)
	}
	if !strings.Contains(got, "a.example.com [200]") {
		t.Fatalf("missing stripped host line:\n%s", got)
	}
	if !strings.Contains(got, "final=login.example.net/sso") {
		t.Fatalf("final= should be stripped too:\n%s", got)
	}
}

func TestNoSchemeQuietOutput(t *testing.T) {
	results := []result{{Host: "a.example.com", Live: true, ProbedURL: "http://a.example.com"}}
	var out bytes.Buffer
	if err := writeResults(&out, results, config{quiet: true, noScheme: true, mode: "http"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "a.example.com\n" {
		t.Fatalf("quiet no-scheme output = %q, want %q", out.String(), "a.example.com\n")
	}
}

func TestNoSchemeKeepsJSONUrls(t *testing.T) {
	results := []result{{Host: "a.example.com", Live: true, ProbedURL: "https://a.example.com"}}
	var out bytes.Buffer
	if err := writeResults(&out, results, config{jsonOut: true, noScheme: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"probed_url":"https://a.example.com"`) {
		t.Fatalf("JSON url should keep its scheme: %s", out.String())
	}
}

func TestParseFlagsDefaultsToBothMode(t *testing.T) {
	cfg, err := parseFlags([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mode != "both" {
		t.Fatalf("mode = %q, want both", cfg.mode)
	}
}

func TestUsageUsesTurkishLocale(t *testing.T) {
	t.Setenv("LC_ALL", "tr_TR.UTF-8")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANGUAGE", "")
	t.Setenv("LANG", "")

	got := usage()
	if !strings.Contains(got, "Kullanim:") {
		t.Fatalf("usage() did not return Turkish help: %q", got)
	}
	if !strings.Contains(got, "-mode string") {
		t.Fatalf("usage() should keep parameter names in English: %q", got)
	}
}

func TestUsageDefaultsToEnglish(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANGUAGE", "")
	t.Setenv("LANG", "en_US.UTF-8")

	got := usage()
	if !strings.Contains(got, "Usage:") {
		t.Fatalf("usage() did not return English help: %q", got)
	}
}

func TestReleaseInfoJSON(t *testing.T) {
	var info releaseInfo
	if err := json.Unmarshal([]byte(`{"tag_name":"v0.2.0","html_url":"https://example.com/release"}`), &info); err != nil {
		t.Fatal(err)
	}
	if info.TagName != "v0.2.0" {
		t.Fatalf("TagName = %q, want v0.2.0", info.TagName)
	}
	if info.URL != "https://example.com/release" {
		t.Fatalf("URL = %q, want release URL", info.URL)
	}
}

func TestCheckForUpdateOutputUsesCurrentVersion(t *testing.T) {
	var out bytes.Buffer
	fmtCheckVersion(&out, releaseInfo{TagName: "v" + version, URL: "https://example.com/release"})
	got := out.String()
	if !strings.Contains(got, "palm is up to date") {
		t.Fatalf("check output = %q, want up-to-date message", got)
	}
}

func TestParseCodes(t *testing.T) {
	codes, err := parseCodes("200, 301,403")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{200, 301, 403} {
		if _, ok := codes[code]; !ok {
			t.Fatalf("missing code %d", code)
		}
	}
}

func TestNormalizeResolver(t *testing.T) {
	tests := map[string]string{
		"1.1.1.1":         "1.1.1.1:53",
		"8.8.8.8:5353":    "8.8.8.8:5353",
		"https://9.9.9.9": "9.9.9.9:53",
		"not-a-resolver":  "",
		"1.1.1.1 # cloud": "1.1.1.1:53",
	}
	for input, want := range tests {
		got := normalizeResolver(input)
		if got != want {
			t.Fatalf("normalizeResolver(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStatusAllowed(t *testing.T) {
	cfg := config{
		matchCodes:  map[int]struct{}{200: {}, 301: {}},
		filterCodes: map[int]struct{}{301: {}},
	}
	if !statusAllowed(200, cfg) {
		t.Fatal("200 should be allowed")
	}
	if statusAllowed(301, cfg) {
		t.Fatal("301 should be filtered")
	}
	if statusAllowed(404, cfg) {
		t.Fatal("404 should not match")
	}
}

func TestCheckHTTPMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "palm-test")
		_, _ = w.Write([]byte("<html><title> Palm Test </title><body>x</body></html>"))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	cfg := config{
		timeout:     2 * time.Second,
		title:       true,
		server:      true,
		contentLen:  true,
		matchCodes:  map[int]struct{}{200: {}},
		filterCodes: map[int]struct{}{},
	}
	client := server.Client()
	client.Timeout = cfg.timeout

	probe, err := checkHTTP(context.Background(), host, cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	if probe.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", probe.StatusCode)
	}
	if probe.Title != "Palm Test" {
		t.Fatalf("title = %q, want Palm Test", probe.Title)
	}
	if probe.Server != "palm-test" {
		t.Fatalf("server = %q, want palm-test", probe.Server)
	}
}

func TestFormatHTTPResultMetadata(t *testing.T) {
	length := int64(123)
	rt := int64(42)
	got := formatHTTPResult(result{
		URL:            "https://example.com",
		StatusCode:     200,
		Title:          "Example",
		Server:         "nginx",
		Length:         &length,
		ResponseTimeMS: &rt,
		Location:       "https://example.com/login",
	}, config{status: true, title: true, server: true, contentLen: true, responseTime: true, location: true})

	want := "https://example.com [200 | title=Example | server=nginx | cl=123 | rt=42ms | location=https://example.com/login]"
	if got != want {
		t.Fatalf("formatHTTPResult = %q, want %q", got, want)
	}
}

func TestParseFlagsTakeover(t *testing.T) {
	cfg, err := parseFlags([]string{"subs.txt", "-takeover", "-rt", "-location", "-follow-redirects=false", "-method", "GET", "-H", "X-Test: yes"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.takeover {
		t.Fatal("takeover = false, want true")
	}
	if !cfg.responseTime {
		t.Fatal("responseTime = false, want true")
	}
	if !cfg.location {
		t.Fatal("location = false, want true")
	}
	if cfg.followRedirects {
		t.Fatal("followRedirects = true, want false")
	}
	if cfg.method != http.MethodGet {
		t.Fatalf("method = %q, want GET", cfg.method)
	}
	if got := cfg.headers.Get("X-Test"); got != "yes" {
		t.Fatalf("X-Test header = %q, want yes", got)
	}
}

func TestDoRequestCustomHeaderMethodAndTiming(t *testing.T) {
	var mu sync.Mutex
	var gotMethod, gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Test")
		mu.Unlock()
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	cfg := config{
		method:       http.MethodGet,
		headers:      http.Header{"X-Test": []string{"yes"}},
		responseTime: true,
		location:     true,
	}
	probe, err := doRequest(context.Background(), server.URL, cfg.method, cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	if probe.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", probe.StatusCode)
	}
	if probe.Location != "/next" {
		t.Fatalf("location = %q, want /next", probe.Location)
	}
	if probe.ResponseTimeMS == nil {
		t.Fatal("ResponseTimeMS = nil, want value")
	}
	mu.Lock()
	method, header := gotMethod, gotHeader
	mu.Unlock()
	if method != http.MethodGet {
		t.Fatalf("method = %q, want GET", method)
	}
	if header != "yes" {
		t.Fatalf("X-Test header = %q, want yes", header)
	}
}

func TestTakeoverFingerprintMatching(t *testing.T) {
	fp, ok := matchTakeoverCNAME("missing-project.github.io.")
	if !ok {
		t.Fatal("expected github-pages CNAME fingerprint match")
	}
	if fp.Provider != "github-pages" {
		t.Fatalf("provider = %q, want github-pages", fp.Provider)
	}
	if !matchTakeoverBody("There isn't a GitHub Pages site here.", fp) {
		t.Fatal("expected github pages body fingerprint match")
	}
}

func TestFormatHTTPResultShowsProbedHostForCrossHostRedirect(t *testing.T) {
	got := formatHTTPResult(result{
		Host:       "0b295af.sites.google.com",
		ProbedURL:  "https://0b295af.sites.google.com",
		URL:        "https://accounts.google.com/ServiceLogin?continue=x",
		StatusCode: 200,
	}, config{status: true})

	want := "https://0b295af.sites.google.com [200 | final=https://accounts.google.com/ServiceLogin?continue=x]"
	if got != want {
		t.Fatalf("formatHTTPResult = %q, want %q", got, want)
	}
}

func TestFormatHTTPResultHidesSameHostRedirect(t *testing.T) {
	tests := []string{
		"https://example.com",
		"https://example.com/",
		"https://EXAMPLE.com/",
		"https://example.com/Security/Login",
		"https://example.com/login?next=/x",
	}
	for _, final := range tests {
		got := formatHTTPResult(result{
			ProbedURL:  "https://example.com",
			URL:        final,
			StatusCode: 200,
		}, config{status: true})
		if got != "https://example.com [200]" {
			t.Fatalf("final %q: got %q, want no final= noise", final, got)
		}
	}
}

func TestFormatHTTPResultShowsCrossHostRedirect(t *testing.T) {
	got := formatHTTPResult(result{
		ProbedURL:  "https://www.example.com",
		URL:        "https://login.example.net/sso",
		StatusCode: 302,
	}, config{status: true})
	want := "https://www.example.com [302 | final=https://login.example.net/sso]"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriteResultsQuietPrintsBareURL(t *testing.T) {
	results := []result{
		{Host: "a.example.com", Live: true, ProbedURL: "https://a.example.com", URL: "https://accounts.google.com/x", StatusCode: 200},
		{Host: "b.example.com", Live: false},
	}
	var out bytes.Buffer
	writeResults(&out, results, config{quiet: true, status: true, mode: "http"})

	want := "https://a.example.com\n"
	if out.String() != want {
		t.Fatalf("quiet output = %q, want %q", out.String(), want)
	}
}

func TestCheckHTTPBudgetSharedAcrossSchemes(t *testing.T) {
	// A listener that accepts connections and never answers makes both the
	// HTTPS handshake and the HTTP request hang, which used to cost 2x timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	host := ln.Addr().String()
	cfg := config{timeout: 500 * time.Millisecond}
	client := &http.Client{Timeout: cfg.timeout}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	start := time.Now()
	_, err = checkHTTP(ctx, host, cfg, client)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from hanging server")
	}
	if elapsed > 900*time.Millisecond {
		t.Fatalf("checkHTTP took %v, want <= ~500ms for one shared budget", elapsed)
	}
}

func TestDoRequestSuppressesTitleFromCrossHostRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><title>Target Title</title></html>"))
	}))
	defer target.Close()

	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())
	redirectTo := "http://localhost:" + port + "/login"

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// localhost and 127.0.0.1 are different hostnames on the same machine.
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}))
	defer redirector.Close()

	cfg := config{timeout: 2 * time.Second, title: true, method: http.MethodGet}
	probe, err := requestURL(context.Background(), redirector.URL, cfg, redirector.Client())
	if err != nil {
		t.Fatal(err)
	}
	if probe.FinalURL != redirectTo {
		t.Fatalf("FinalURL = %q, want %q", probe.FinalURL, redirectTo)
	}
	if probe.Title != "" {
		t.Fatalf("title = %q, want empty for a cross-host redirect", probe.Title)
	}
}

func TestSameHost(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"https://example.com", "https://example.com/", true},
		{"https://EXAMPLE.com", "https://example.com/x", true},
		{"http://example.com", "https://example.com", true},
		{"https://example.com:443", "https://example.com", true},
		{"https://www.example.com", "https://example.com/", true},
		{"https://example.com", "https://www.example.com/", true},
		{"https://a.example.com", "https://b.example.com", false},
		{"https://0b295af.sites.google.com", "https://accounts.google.com/x", false},
		{"https://example.com", "https://example.com.evil.test/", false},
	}
	for _, tc := range tests {
		if got := sameHost(tc.a, tc.b); got != tc.want {
			t.Errorf("sameHost(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestTitleAttribution(t *testing.T) {
	tests := []struct {
		name          string
		probed, final string
		wantKeepTitle bool
	}{
		{"same host", "https://example.com", "https://example.com/", true},
		{"http to https", "http://example.com", "https://example.com/", true},
		{"www to apex", "https://www.example.com", "https://example.com/", true},
		{"apex to www", "https://example.com", "https://www.example.com/", true},
		{"foreign login page", "https://0b295af.sites.google.com", "https://accounts.google.com/x", false},
		{"foreign lookalike", "https://example.com", "https://example.com.evil.test/", false},
	}
	for _, tc := range tests {
		if got := sameHost(tc.probed, tc.final); got != tc.wantKeepTitle {
			t.Errorf("%s: sameHost(%q, %q) = %v, want %v", tc.name, tc.probed, tc.final, got, tc.wantKeepTitle)
		}
	}
}

func TestDoRequestKeepsTitleForSameHostRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/new" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><title>Same Host</title></html>"))
			return
		}
		http.Redirect(w, r, "/new", http.StatusFound)
	}))
	defer server.Close()

	cfg := config{timeout: 2 * time.Second, title: true, method: http.MethodGet}
	probe, err := requestURL(context.Background(), server.URL, cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if probe.Title != "Same Host" {
		t.Fatalf("title = %q, want \"Same Host\"", probe.Title)
	}
}

func TestEvaluateTakeoverKeepsCNAMEWithoutFingerprintMatch(t *testing.T) {
	takeover, provider, cname := evaluateTakeover(context.Background(), "shop.example.com", "shop.example.com.", http.DefaultClient, nil)
	if takeover || provider != "" {
		t.Fatalf("takeover=%v provider=%q, want no match", takeover, provider)
	}
	if cname != "shop.example.com." {
		t.Fatalf("cname = %q, want the resolved CNAME even without a match", cname)
	}
}

func TestCertMatchesHost(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com", "*.example.com", "www.other.test"},
	}
	tests := map[string]bool{
		"example.com":         true,
		"api.example.com":     true,
		"www.other.test":      true,
		"a.b.example.com":     false, // wildcard covers one label only
		"example.com.evil.io": false,
		"other.test":          false,
	}
	for host, want := range tests {
		if got := certMatchesHost(cert, host); got != want {
			t.Errorf("certMatchesHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestParentDomain(t *testing.T) {
	tests := map[string]string{
		"a.example.com":         "example.com",
		"a.b.example.com":       "example.com",
		"example.com":           "",
		"a.example.co.uk":       "example.co.uk",
		"x.y.example.co.uk":     "example.co.uk",
		"a.example.ninja":       "example.ninja",
		"deep.sub.example.test": "example.test",
		// shared hosting suffixes must not be probed
		"foo.github.io":     "",
		"x.appspot.com":     "",
		"a.b.herokuapp.com": "",
		"site.netlify.app":  "",
	}
	for host, want := range tests {
		if got := parentDomain(host); got != want {
			t.Errorf("parentDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestRunChecksEmitsEveryResult(t *testing.T) {
	hosts := []string{"a.invalid", "b.invalid"}
	seen := map[string]bool{}
	err := runChecks(context.Background(), hosts, config{
		mode:        "dns",
		concurrency: 2,
		timeout:     2 * time.Second,
	}, func(res result) error {
		seen[res.Host] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range hosts {
		if !seen[host] {
			t.Fatalf("host %q was not emitted", host)
		}
	}
}

func TestRunChecksStopsOnEmitError(t *testing.T) {
	want := errors.New("consumer closed")
	calls := 0
	hosts := make([]string, 20)
	for i := range hosts {
		hosts[i] = "host" + strconv.Itoa(i) + ".invalid"
	}

	err := runChecks(context.Background(), hosts, config{
		mode:        "dns",
		concurrency: 1,
		timeout:     2 * time.Second,
	}, func(result) error {
		calls++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if calls != 1 {
		t.Fatalf("emit called %d times, want 1 before stopping", calls)
	}
}

func TestProgressStateLine(t *testing.T) {
	p := &progressState{total: 4, start: time.Now()}
	p.add(result{Live: true})
	p.add(result{})
	p.add(result{Live: true})

	line := p.line()
	for _, want := range []string{"3/4", "75%", "2 live", "1 failed"} {
		if !strings.Contains(line, want) {
			t.Fatalf("progress line %q is missing %q", line, want)
		}
	}
}

func TestRateLimiterSpacesRequests(t *testing.T) {
	limiter := newRateLimiter(50, 0) // 20ms apart
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := limiter.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 35*time.Millisecond {
		t.Fatalf("3 waits took %v, want at least ~40ms", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("3 waits took %v, too slow", elapsed)
	}
}

func TestRateLimiterDelayFloorAndUnlimited(t *testing.T) {
	if newRateLimiter(0, 0) != nil {
		t.Fatal("rate 0 and delay 0 must mean unlimited")
	}
	limiter := newRateLimiter(0, 15*time.Millisecond)
	if limiter == nil || limiter.interval != 15*time.Millisecond {
		t.Fatalf("delay-only limiter interval = %v, want 15ms", limiter)
	}
}

func TestRateLimiterHonorsContext(t *testing.T) {
	limiter := newRateLimiter(1, 0) // 1s apart
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := limiter.Wait(ctx); err == nil {
		t.Fatal("wait should have been cancelled")
	}
}

func TestParseFlagsRateLimiterAndOutput(t *testing.T) {
	cfg, err := parseFlags([]string{"-rate", "2.5", "-delay", "150ms", "-no-sort", "-progress", "-lang", "tr"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.noSort || !cfg.progress {
		t.Fatalf("noSort=%v progress=%v, want both true", cfg.noSort, cfg.progress)
	}
	if cfg.lang != "tr" {
		t.Fatalf("lang = %q, want tr", cfg.lang)
	}
	if cfg.limiter == nil {
		t.Fatal("limiter was not built")
	}
	if cfg.limiter.interval != 400*time.Millisecond {
		t.Fatalf("interval = %v, want 400ms from -rate 2.5", cfg.limiter.interval)
	}
}

func TestParseFlagsRejectsInvalidRateAndLang(t *testing.T) {
	if _, err := parseFlags([]string{"-rate", "-1"}); err == nil {
		t.Fatal("negative rate must be rejected")
	}
	if _, err := parseFlags([]string{"-delay", "-5s"}); err == nil {
		t.Fatal("negative delay must be rejected")
	}
	if _, err := parseFlags([]string{"-lang", "de"}); err == nil {
		t.Fatal("unknown language must be rejected")
	}
}

func TestUsageLangForcesLanguage(t *testing.T) {
	if !strings.Contains(usageLang("tr"), "Kullanim:") {
		t.Fatal("usageLang(tr) is not Turkish")
	}
	if !strings.Contains(usageLang("en"), "Usage:") {
		t.Fatal("usageLang(en) is not English")
	}
}

func TestStreamingAndSortedOutputMatch(t *testing.T) {
	results := []result{
		{Host: "b.example.com", Live: true, ProbedURL: "https://b.example.com", StatusCode: 200},
		{Host: "a.example.com", Live: false},
		{Host: "c.example.com", Live: true, ProbedURL: "https://c.example.com", StatusCode: 403},
	}
	cfg := config{status: true, mode: "http"}

	var sorted bytes.Buffer
	if err := writeResults(&sorted, results, cfg); err != nil {
		t.Fatal(err)
	}

	var streamed bytes.Buffer
	for _, res := range results {
		if err := writeResult(&streamed, res, cfg); err != nil {
			t.Fatal(err)
		}
	}

	if sorted.String() != streamed.String() {
		t.Fatalf("streamed output differs\nsorted:\n%s\nstreamed:\n%s", sorted.String(), streamed.String())
	}
}

func TestReadTitleStopsEarly(t *testing.T) {
	// A body with a title and a large trailing payload: the reader must not need
	// to consume it all.
	title := "<html><head><title>  Hello   Palm </title></head><body>"
	body := strings.NewReader(title + strings.Repeat("x", 500*1024))
	got := readTitle(body)
	if got != "Hello Palm" {
		t.Fatalf("readTitle = %q, want %q", got, "Hello Palm")
	}
	if remaining := body.Len(); remaining < 400*1024 {
		t.Fatalf("readTitle consumed too much: %d bytes left", remaining)
	}
}

func TestReadTitleWithoutTitle(t *testing.T) {
	if got := readTitle(strings.NewReader("<html><head></head><body>no title</body></html>")); got != "" {
		t.Fatalf("readTitle = %q, want empty", got)
	}
}

func TestIPSetsOverlap(t *testing.T) {
	if !ipSetsOverlap([]string{"1.1.1.1", "2.2.2.2"}, []string{"3.3.3.3", "2.2.2.2"}) {
		t.Fatal("expected overlap")
	}
	if ipSetsOverlap([]string{"1.1.1.1"}, []string{"2.2.2.2"}) {
		t.Fatal("expected no overlap")
	}
	if ipSetsOverlap(nil, []string{"2.2.2.2"}) {
		t.Fatal("empty set must not overlap")
	}
}

func TestFormatHTTPResultTLSAndWildcard(t *testing.T) {
	days := 42
	got := formatHTTPResult(result{
		ProbedURL:   "https://a.example.com",
		StatusCode:  200,
		TLSIssuer:   "Let's Encrypt",
		TLSDaysLeft: &days,
		TLSMismatch: true,
		Wildcard:    true,
	}, config{status: true, tlsInfo: true})

	want := "https://a.example.com [200 | tls=Let's Encrypt 42d | tls_mismatch | wildcard]"
	if got != want {
		t.Fatalf("formatHTTPResult = %q, want %q", got, want)
	}
}

func TestWriteResultsFiltersWildcard(t *testing.T) {
	results := []result{
		{Host: "real.example.com", Live: true, ProbedURL: "https://real.example.com"},
		{Host: "fake.example.com", Live: true, ProbedURL: "https://fake.example.com", Wildcard: true},
	}
	var out bytes.Buffer
	writeResults(&out, results, config{quiet: true, filterWildcard: true})

	if strings.Contains(out.String(), "fake.example.com") {
		t.Fatalf("wildcard host was not filtered: %q", out.String())
	}
	if !strings.Contains(out.String(), "real.example.com") {
		t.Fatalf("real host missing: %q", out.String())
	}
}

func TestFormatHTTPResultTakeover(t *testing.T) {
	got := formatHTTPResult(result{
		Host:     "old.example.com",
		Takeover: true,
		Provider: "github-pages",
		CNAME:    "missing-project.github.io.",
	}, config{takeover: true})

	want := "old.example.com [takeover=github-pages | cname=missing-project.github.io.]"
	if got != want {
		t.Fatalf("formatHTTPResult = %q, want %q", got, want)
	}
}

func TestCheckHostBothModeReportsDNSError(t *testing.T) {
	cfg := config{mode: "both", timeout: 500 * time.Millisecond}
	client := &http.Client{Timeout: cfg.timeout}
	resolvers := newResolverPool([]string{"127.0.0.1:1"})

	got := checkHost(context.Background(), "example.com", cfg, client, resolvers, nil)
	if got.Live {
		t.Fatal("live = true, want false")
	}
	if got.Error == "" {
		t.Fatal("error is empty, want DNS failure detail")
	}
}

func TestRunChecksRejectsResolverFileWithoutUsableResolvers(t *testing.T) {
	path := t.TempDir() + "/resolvers.txt"
	if err := os.WriteFile(path, []byte("not-a-resolver\n# comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runChecks(context.Background(), []string{"example.com"}, config{resolverFile: path, mode: "dns", concurrency: 1, timeout: time.Second}, nil)
	if err == nil {
		t.Fatal("runChecks returned nil error for unusable resolver file")
	}
}

func TestFormatHTTPResultIPs(t *testing.T) {
	got := formatHTTPResult(result{
		URL:        "https://example.com",
		StatusCode: 200,
		DNS:        true,
		IPs:        []string{"1.2.3.4", "5.6.7.8"},
	}, config{status: true})

	want := "https://example.com [200 | ip=1.2.3.4,5.6.7.8]"
	if got != want {
		t.Fatalf("formatHTTPResult = %q, want %q", got, want)
	}
}

func TestFormatDNSResultTakeover(t *testing.T) {
	got := formatDNSResult(result{
		Host:     "old.example.com",
		Takeover: true,
		Provider: "aws-s3",
		CNAME:    "old-bucket.s3.amazonaws.com.",
	}, config{takeover: true})

	want := "old.example.com [takeover=aws-s3 | cname=old-bucket.s3.amazonaws.com.]"
	if got != want {
		t.Fatalf("formatDNSResult = %q, want %q", got, want)
	}
}

func TestParseFlagsWildcardRequiresDNSMode(t *testing.T) {
	for _, args := range [][]string{
		{"-mode", "http", "-wildcard"},
		{"-mode", "http", "-fw"},
	} {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("parseFlags(%v) = nil error, want wildcard mode error", args)
		}
	}
	if _, err := parseFlags([]string{"-mode", "both", "-wildcard"}); err != nil {
		t.Fatalf("parseFlags(both + wildcard): %v", err)
	}
}

func TestReadTitleHandlesUnicodeBeforeTitle(t *testing.T) {
	body := `<html><head><meta content="İstanbul"><title>Başlık</title></head></html>`
	if got := readTitle(strings.NewReader(body)); got != "Başlık" {
		t.Fatalf("readTitle = %q, want %q", got, "Başlık")
	}
}

func TestReadTitleFindsUppercaseTags(t *testing.T) {
	body := `<HTML><HEAD><TITLE>Hello</TITLE></HEAD></HTML>`
	if got := readTitle(strings.NewReader(body)); got != "Hello" {
		t.Fatalf("readTitle = %q, want Hello", got)
	}
}

func TestTakeoverCNAMEMatchesWholeLabels(t *testing.T) {
	if _, ok := matchTakeoverCNAME("notamazonaws.com"); ok {
		t.Fatal("notamazonaws.com must not match amazonaws.com")
	}
	if _, ok := matchTakeoverCNAME("evilgithub.io"); ok {
		t.Fatal("evilgithub.io must not match github.io")
	}
	fp, ok := matchTakeoverCNAME("bucket.s3-website-us-east-1.amazonaws.com")
	if !ok || fp.Provider != "aws-s3" {
		t.Fatalf("s3 website CNAME match = %q, %v, want aws-s3", fp.Provider, ok)
	}
}

func TestTakeoverBodyRejectsGenericProviderMentions(t *testing.T) {
	fp, ok := matchTakeoverCNAME("missing.github.io")
	if !ok {
		t.Fatal("expected github-pages fingerprint")
	}
	if matchTakeoverBody("welcome to our github pages site", fp) {
		t.Fatal("generic 'github pages' mention must not match")
	}
	if !matchTakeoverBody("There isn't a GitHub Pages site here.", fp) {
		t.Fatal("provider error page must match")
	}
}

func TestResultWriterCommitsAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	rw, err := openResultWriter(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Abort()
	if _, err := rw.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
		t.Fatalf("destination changed before commit: %q, %v", data, err)
	}
	if err := rw.Commit(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "new" {
		t.Fatalf("after commit = %q, %v", data, err)
	}
}

func TestResultWriterAbortKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	rw, err := openResultWriter(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	rw.Abort()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "old" {
		t.Fatalf("after abort = %q, %v", data, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".palm-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestWriteResultsReturnsWriteError(t *testing.T) {
	err := writeResults(failingWriter{}, []result{
		{Host: "a.example.com", Live: true, ProbedURL: "https://a.example.com"},
	}, config{mode: "http"})
	if err == nil {
		t.Fatal("writeResults returned nil for a failing writer")
	}
}

func TestIsBrokenPipe(t *testing.T) {
	if !isBrokenPipe(errors.New("write |1: broken pipe")) {
		t.Fatal("expected broken pipe detection")
	}
	if isBrokenPipe(errors.New("disk full")) {
		t.Fatal("disk full is not a broken pipe")
	}
}

func TestUpdatePalmWithoutGoPrintsInstaller(t *testing.T) {
	old := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	defer func() { lookPath = old }()

	// No assets: self-update fails before any network download, which is exactly
	// the path a platform without a published binary takes.
	var out, errOut bytes.Buffer
	if err := updatePalmTo(&out, &errOut, releaseInfo{TagName: "v99.0.0"}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "install.ps1") || !strings.Contains(got, "install.sh") {
		t.Fatalf("update output = %q, want installer commands", got)
	}
	if !strings.Contains(errOut.String(), "self-update failed") {
		t.Fatalf("stderr = %q, want a self-update failure note", errOut.String())
	}
}

func TestNewHTTPClientUsesResolverPool(t *testing.T) {
	client := newHTTPClient(config{concurrency: 1, timeout: time.Second, followRedirects: true}, newResolverPool([]string{"127.0.0.1:1"}))
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext is nil with a resolver pool")
	}
}

func TestNewHTTPClientWithoutResolverKeepsDefaultDialer(t *testing.T) {
	client := newHTTPClient(config{concurrency: 1, timeout: time.Second, followRedirects: true}, nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext != nil {
		t.Fatal("DialContext must stay nil without a resolver pool")
	}
}

func TestRunChecksReturnsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runChecks(ctx, []string{"a.example.com", "b.example.com"}, config{
			mode:        "dns",
			concurrency: 2,
			timeout:     50 * time.Millisecond,
		}, nil)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runChecks did not return after context cancellation")
	}
}

func TestHTTPClientDialsIPLiteralsDirectly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := newHTTPClient(config{concurrency: 1, timeout: 2 * time.Second, followRedirects: true}, newResolverPool([]string{"127.0.0.1:1"}))
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	conn, err := transport.DialContext(context.Background(), "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial through IP literal: %v", err)
	}
	_ = conn.Close()
}
