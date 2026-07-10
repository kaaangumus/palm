package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"api.example.com":                       "api.example.com",
		"HTTPS://App.Example.COM/login":         "app.example.com",
		"cdn.example.com.":                      "cdn.example.com",
		"test.example.com 1.2.3.4":              "test.example.com",
		"\"quoted.example.com\"":                "quoted.example.com",
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

	probe, err := checkHTTP(host, cfg, client)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", r.Method)
		}
		if got := r.Header.Get("X-Test"); got != "yes" {
			t.Fatalf("X-Test header = %q, want yes", got)
		}
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
	probe, err := doRequest(server.URL, cfg.method, cfg, client)
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
