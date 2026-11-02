package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Baba01hacker666/z1pfd/internal/httpx"
)

// Printer interface to avoid import cycle with output package
type Printer interface {
	Info(format string, args ...interface{})
	Progress(done, total int64, pct float64, found int64)
}

// Config holds scanner configuration
type Config struct {
	Target      string
	Concurrency int
	Timeout     time.Duration
	Extensions  []string
	Proxy       string
	Depth       int
	NoRedirect  bool
	RandomUA    bool
	SpoofIP     bool
	MinSize     int64
	RateLimit   int
	Verbose     bool
	ResumeFile  string
	NoProgress  bool
	// Ctx enables graceful shutdown on interrupt. nil = run to completion.
	Ctx context.Context
	// shared WAF-aware adaptive throttle (created by Run)
	state *adaptiveThrottle
}

// adaptiveThrottle implements WAF-aware pacing shared by all workers:
// when a WAF/rate-limiter trips, every worker slows down until the
// exponential backoff deadline passes, and the failed request is retried once.
type adaptiveThrottle struct {
	mu      sync.Mutex
	until   time.Time
	backoff time.Duration
	names   map[string]bool
}

func newAdaptiveThrottle() *adaptiveThrottle {
	return &adaptiveThrottle{
		backoff: 1500 * time.Millisecond, // first slow-down after a WAF hit
		names:   make(map[string]bool),
	}
}

func (t *adaptiveThrottle) wait() {
	if t == nil {
		return
	}
	t.mu.Lock()
	until := t.until
	t.mu.Unlock()
	if d := time.Until(until); d > 0 {
		time.Sleep(d)
	}
}

// trip records a WAF hit and extends the global backoff deadline
func (t *adaptiveThrottle) trip() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.backoff *= 2
	if t.backoff > 12*time.Second {
		t.backoff = 12 * time.Second
	}
	if dl := time.Now().Add(t.backoff); dl.After(t.until) {
		t.until = dl
	}
}

func (t *adaptiveThrottle) detected(name string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.names[name] = true
	t.mu.Unlock()
}

func (t *adaptiveThrottle) detectedNames() []string {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	names := make([]string, 0, len(t.names))
	for n := range t.names {
		names = append(names, n)
	}
	t.mu.Unlock()
	sort.Strings(names)
	return names
}

// adaptiveWait blocks until the shared backoff deadline passes (if any)
func adaptiveWait(t *adaptiveThrottle) {
	if t != nil {
		t.wait()
	}
}

// Result represents a found archive
type Result struct {
	URL          string        `json:"url"`
	Status       int           `json:"status"`
	Size         int64         `json:"size"`
	ContentType  string        `json:"content_type"`
	ResponseTime time.Duration `json:"response_time_ms"`
	MagicMatch   bool          `json:"magic_bytes_match"`
}

// magic byte signatures for archive types (checked against the first bytes of the body)
var magicBytes = map[string][]byte{
	".zip":    {0x50, 0x4B, 0x03, 0x04}, // PK..
	".rar":    {0x52, 0x61, 0x72, 0x21}, // Rar!
	".7z":     {0x37, 0x7A, 0xBC, 0xAF}, // 7z
	".tar.gz": {0x1F, 0x8B},             // gzip
	".gz":     {0x1F, 0x8B},
	".bz2":    {0x42, 0x5A, 0x68}, // BZh
	// plain .tar files have no reliable magic in the first bytes (ustar sits at
	// offset 257), so they are detected via Content-Type instead
}

var validContentTypes = []string{
	"application/zip",
	"application/x-zip",
	"application/x-zip-compressed",
	"application/octet-stream",
	"application/x-rar",
	"application/x-rar-compressed",
	"application/x-7z-compressed",
	"application/x-tar",
	"application/gzip",
	"application/x-gzip",
	"application/x-bzip2",
	"application/download",
	"binary/octet-stream",
}

// Run executes the scanner and returns all found results
func Run(cfg *Config, paths []string, printer Printer) []Result {
	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	cfg.state = newAdaptiveThrottle()

	// normalize extensions once (lowercase, trimmed)
	for i, ext := range cfg.Extensions {
		cfg.Extensions[i] = strings.ToLower(strings.TrimSpace(ext))
	}

	// load resume state
	resumeState := loadResumeState(cfg.ResumeFile)
	scanned := resumeState.Scanned

	// filter already scanned
	var todo []string
	for _, p := range paths {
		fullURL := cfg.Target + p
		if !scanned[fullURL] {
			todo = append(todo, p)
		}
	}

	if len(scanned) > 0 {
		printer.Info("Resuming: skipping %d already-scanned URLs", len(scanned))
	}

	var results []Result

	total := len(todo)
	if total == 0 {
		return results
	}

	var done atomic.Int64
	var found atomic.Int64
	interrupted := false

	jobs := make(chan string, cfg.Concurrency*2)
	resultCh := make(chan Result, 100)
	var wg sync.WaitGroup

	// rate limiter
	var ticker *time.Ticker
	if cfg.RateLimit > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(cfg.RateLimit))
		defer ticker.Stop()
	}

	client := buildClient(cfg)

	// background progress updater to prevent lock contention on stdout
	progressDone := make(chan struct{})
	if !cfg.NoProgress {
		// progressDone is closed only by this goroutine (via defer)
		go func() {
			defer close(progressDone)
			progTicker := time.NewTicker(250 * time.Millisecond)
			defer progTicker.Stop()
			for {
				select {
				case <-progTicker.C:
					d := done.Load()
					if d >= int64(total) {
						return
					}
					pct := float64(d) / float64(total) * 100
					printer.Progress(d, int64(total), pct, found.Load())
				case <-ctx.Done():
					return
				}
			}
		}()
	} else {
		close(progressDone)
	}

	var scannedMu sync.Mutex

	// spawn workers
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case path, ok := <-jobs:
					if !ok {
						return
					}
					if ticker != nil {
						<-ticker.C
					}
					fullURL := cfg.Target + path
					result, ok := probe(client, cfg, fullURL)

					d := done.Add(1)
					if !cfg.NoProgress && d == int64(total) {
						pct := float64(d) / float64(total) * 100
						printer.Progress(d, int64(total), pct, found.Load())
					}

					if ok {
						found.Add(1)
						resultCh <- result
					}

					// save resume state (thread-safe)
					if cfg.ResumeFile != "" {
						scannedMu.Lock()
						scanned[fullURL] = true
						scannedMu.Unlock()
					}
				}
			}
		}()
	}

	// feed jobs (stops early if ctx is canceled)
	feeder := make(chan struct{})
	go func() {
		defer close(feeder)
		for _, path := range todo {
			select {
			case jobs <- path:
			case <-ctx.Done():
				return
			}
		}
		close(jobs)
	}()

	// collect results
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for r := range resultCh {
			results = append(results, r)
		}
	}()

	// auto-save resume state periodically so interrupted scans can resume
	runSaveTick := func() {}
	if cfg.ResumeFile != "" {
		saveStop := make(chan struct{})
		go func() {
			saver := time.NewTicker(10 * time.Second)
			defer saver.Stop()
			for {
				select {
				case <-saver.C:
					scannedMu.Lock()
					saveResumeState(cfg.ResumeFile, &resumeData{Scanned: scanned})
					scannedMu.Unlock()
				case <-saveStop:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
		runSaveTick = func() { close(saveStop) }
	}

	wg.Wait()

	// decide interruption before stopping helpers
	select {
	case <-ctx.Done():
		interrupted = true
	default:
	}

	<-feeder        // wait for feeder to stop (it closes jobs on normal completion)
	runSaveTick()   // stop periodic saver
	close(resultCh) // safe: no more producers after wg.Wait()
	resultWg.Wait()
	<-progressDone // wait for progress goroutine; it is the only closer

	if interrupted {
		fmt.Println()
		printer.Info("Interrupted — partial progress saved, re-run with same -resume to continue")
	}

	// report WAF mitigation that kicked in during this scan
	if names := cfg.state.detectedNames(); len(names) > 0 {
		printer.Info("WAF detected: %s — traffic was auto-slowed and requests retried once after backoff", strings.Join(names, ", "))
	}

	// save final resume state
	if cfg.ResumeFile != "" {
		scannedMu.Lock()
		saveResumeState(cfg.ResumeFile, &resumeData{Scanned: scanned})
		scannedMu.Unlock()
	}

	return results
}

func probe(client *http.Client, cfg *Config, fullURL string) (Result, bool) {
	adaptiveWait(cfg.state)
	start := time.Now()

	// HEAD first: cheap existence check
	head, headOK, waf := doRequest(client, cfg, "HEAD", fullURL, start)
	if waf {
		// WAF/rate-limit tripped: slow down globally, retry this request once
		cfg.state.trip()
		adaptiveWait(cfg.state)
		head, headOK, _ = doRequest(client, cfg, "HEAD", fullURL, start)
	}

	if headOK {
		adaptiveWait(cfg.state)
		got, gotOK, waf := doRequest(client, cfg, "GET", fullURL, start)
		if waf {
			cfg.state.trip()
			adaptiveWait(cfg.state)
			got, gotOK, _ = doRequest(client, cfg, "GET", fullURL, start)
		}
		if gotOK {
			return got, true
		}
		if got.Status != 0 {
			return got, false // GET disproved it (404, HTML body, tiny size)
		}
		// GET itself failed (network hiccup) — fall back to the HEAD result
		return head, true
	}

	// fallback to GET when HEAD is unsupported or failed entirely
	if head.Status == 0 || head.Status == 405 {
		adaptiveWait(cfg.state)
		got, gotOK, waf := doRequest(client, cfg, "GET", fullURL, start)
		if waf {
			cfg.state.trip()
			adaptiveWait(cfg.state)
			got, gotOK, _ = doRequest(client, cfg, "GET", fullURL, start)
		}
		return got, gotOK
	}

	return head, false
}

func doRequest(client *http.Client, cfg *Config, method, fullURL string, start time.Time) (Result, bool, bool) {
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return Result{}, false, false
	}

	// realistic User-Agent + browser-matched header set
	httpx.Apply(req, cfg.RandomUA, cfg.SpoofIP)

	resp, err := client.Do(req)
	if err != nil {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[DBG] %s %s → %v\n", method, fullURL, err)
		}
		return Result{}, false, false
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			// Drain up to 32KB to allow connection reuse for small responses (like 404 pages)
			io.CopyN(io.Discard, resp.Body, 32*1024)
			resp.Body.Close()
		}
	}()

	elapsed := time.Since(start)

	result := Result{
		URL:          fullURL,
		Status:       resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		ResponseTime: elapsed,
	}

	// size from Content-Length
	result.Size = resp.ContentLength

	// WAF / rate-limit sniffing happens only where it matters
	wafHit := false
	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		buf := make([]byte, 8192)
		n, _ := io.ReadFull(resp.Body, buf)
		if name := httpx.DetectWAF(resp.Header, string(buf[:n])); name != "" {
			cfg.state.detected(name)
			wafHit = true
		}
		if resp.StatusCode == 429 {
			// rate limited even if no known WAF signature matched
			wafHit = true
		}
	}
	if wafHit {
		return result, false, true
	}

	// check status
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return result, false, false
	}

	// check content type
	ct := strings.ToLower(result.ContentType)
	ctMatch := false
	for _, vct := range validContentTypes {
		if strings.Contains(ct, vct) {
			ctMatch = true
			break
		}
	}

	// reject obvious soft-404 pages: text content served for an archive URL
	if strings.Contains(ct, "text/") {
		return result, false, false
	}

	// check magic bytes (read first 8 bytes)
	var magic []byte
	if method == "GET" {
		buf := make([]byte, 8)
		n, _ := io.ReadFull(resp.Body, buf)
		magic = buf[:n]
		result.MagicMatch = checkMagic(magic)
	}

	// determine extension from URL
	lowerURL := strings.ToLower(fullURL)

	// size check
	if cfg.MinSize > 0 && result.Size > 0 && result.Size < cfg.MinSize {
		return result, false, false
	}

	// accept if: content type matches, magic bytes match, or Content-Length > 1000 and extension matches
	extMatch := false
	for _, ext := range cfg.Extensions {
		if strings.HasSuffix(lowerURL, ext) {
			extMatch = true
			break
		}
	}

	if ctMatch || result.MagicMatch || (extMatch && result.Size > 1000) {
		return result, true, false
	}

	// unknown transfer size (chunked) with matching extension: still worth reporting
	if extMatch && result.Size == -1 && result.Status == 200 {
		return result, true, false
	}

	return result, false, false
}

func checkMagic(data []byte) bool {
	for _, sig := range magicBytes {
		if len(data) >= len(sig) && bytes.Equal(data[:len(sig)], sig) {
			return true
		}
	}
	return false
}

func buildClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxConnsPerHost:       cfg.Concurrency,
		MaxIdleConns:          cfg.Concurrency * 2,
		MaxIdleConnsPerHost:   cfg.Concurrency,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}

	if cfg.NoRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	return client
}

// resume state management

// resumeData holds already-scanned URLs for -resume support
type resumeData struct {
	Scanned map[string]bool
}

func loadResumeState(path string) *resumeData {
	rd := &resumeData{Scanned: make(map[string]bool)}
	if path == "" {
		return rd
	}
	f, err := os.Open(path)
	if err != nil {
		return rd
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			rd.Scanned[line] = true
		}
	}
	return rd
}

func saveResumeState(path string, rd *resumeData) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for u := range rd.Scanned {
		fmt.Fprintln(w, u)
	}
	w.Flush()
}
