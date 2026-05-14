package scanner

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	MinSize     int64
	RateLimit   int
	Verbose     bool
	ResumeFile  string
	NoProgress  bool
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

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"curl/8.7.1",
	"python-requests/2.31.0",
	"Go-http-client/1.1",
	"Wget/1.21.4",
	"Java/17.0.1",
	"axios/1.6.0",
}

// magic byte signatures for archive types
var magicBytes = map[string][]byte{
	".zip":    {0x50, 0x4B, 0x03, 0x04}, // PK..
	".rar":    {0x52, 0x61, 0x72, 0x21}, // Rar!
	".7z":     {0x37, 0x7A, 0xBC, 0xAF}, // 7z
	".tar.gz": {0x1F, 0x8B},             // gzip
	".gz":     {0x1F, 0x8B},
	".bz2":    {0x42, 0x5A, 0x68},       // BZh
	".tar":    {0x75, 0x73, 0x74, 0x61}, // ustar (offset 257, simplified check)
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

	total := len(todo)
	var done atomic.Int64
	var found atomic.Int64

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
	if !cfg.NoProgress {
		go func() {
			progTicker := time.NewTicker(250 * time.Millisecond)
			defer progTicker.Stop()
			for range progTicker.C {
				d := done.Load()
				if d >= int64(total) {
					return
				}
				pct := float64(d) / float64(total) * 100
				printer.Progress(d, int64(total), pct, found.Load())
			}
		}()
	}

	var scannedMu sync.Mutex

	// spawn workers
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
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
		}()
	}

	// feed jobs
	go func() {
		for _, path := range todo {
			jobs <- path
		}
		close(jobs)
	}()

	// collect results
	var results []Result
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for r := range resultCh {
			results = append(results, r)
		}
	}()

	wg.Wait()
	close(resultCh)
	resultWg.Wait()

	// save final resume state
	if cfg.ResumeFile != "" {
		saveResumeState(cfg.ResumeFile, &resumeData{Scanned: scanned})
	}

	return results
}

func probe(client *http.Client, cfg *Config, fullURL string) (Result, bool) {
	start := time.Now()

	// try HEAD first
	result, ok := doRequest(client, cfg, "HEAD", fullURL, start)
	if ok {
		return result, true
	}

	// fallback to GET with limited body read for magic bytes
	if result.Status == 0 || result.Status == 405 {
		result, ok = doRequest(client, cfg, "GET", fullURL, start)
		return result, ok
	}

	return result, false
}

func doRequest(client *http.Client, cfg *Config, method, fullURL string, start time.Time) (Result, bool) {
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return Result{}, false
	}

	// headers
	if cfg.RandomUA {
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	} else {
		req.Header.Set("User-Agent", "z1pfd/1.0 (+https://github.com/doraemoncyberteam)")
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Cache-Control", "no-cache")

	// WAF/CDN bypass headers
	req.Header.Set("X-Forwarded-For", randomIP())
	req.Header.Set("X-Real-IP", randomIP())
	req.Header.Set("X-Originating-IP", randomIP())

	resp, err := client.Do(req)
	if err != nil {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[DBG] %s %s → %v\n", method, fullURL, err)
		}
		return Result{}, false
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

	// check status
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return result, false
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

	// check magic bytes (read first 8 bytes)
	var magic []byte
	if method == "GET" {
		buf := make([]byte, 8)
		n, _ := io.ReadFull(resp.Body, buf)
		magic = buf[:n]
		result.MagicMatch = checkMagic(magic, fullURL)
	}

	// determine extension from URL
	lowerURL := strings.ToLower(fullURL)

	// size check
	if cfg.MinSize > 0 && result.Size > 0 && result.Size < cfg.MinSize {
		return result, false
	}

	// accept if: content type matches, magic bytes match, or Content-Length > 1000 and extension matches
	extMatch := false
	for _, ext := range cfg.Extensions {
		if strings.HasSuffix(lowerURL, ext) {
			extMatch = true
			break
		}
	}

	isHTML := strings.Contains(ct, "text/html")

	if result.MagicMatch {
		return result, true
	}

	if ctMatch && !isHTML {
		return result, true
	}

	if extMatch && result.Size > 1000 && !isHTML {
		return result, true
	}

	// if content-length is > 0 and extension matches, likely a hit
	if extMatch && (result.Size == -1 || result.Size > 0) && result.Status == 200 && !isHTML {
		return result, true
	}

	return result, false
}

func checkMagic(data []byte, urlStr string) bool {
	lurl := strings.ToLower(urlStr)
	for ext, sig := range magicBytes {
		if strings.Contains(lurl, ext) || ext == ".zip" { // always check zip
			if len(data) >= len(sig) && bytes.Equal(data[:len(sig)], sig) {
				return true
			}
		}
	}
	return false
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223)+1, rand.Intn(254)+1,
		rand.Intn(254)+1, rand.Intn(254)+1)
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

type resumeData struct {
	Scanned map[string]bool `json:"scanned"`
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

	// save as JSON for results + newline-delimited for scanned
	data, _ := json.MarshalIndent(rd, "", "  ")
	_ = data

	w := bufio.NewWriter(f)
	for u := range rd.Scanned {
		fmt.Fprintln(w, u)
	}
	w.Flush()
}
