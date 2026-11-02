// Package httpx holds the shared HTTP personality of the tool: realistic
// browser UA + header profiles, WAF fingerprinting and client building.
// It is used by both the extractor (page intelligence) and the scanner
// (archive probing) so every request looks like a real browser or a plain
// file-fetching tool, never like default Go HTTP.
package httpx

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UAProfile pairs a modern User-Agent with matching browser-specific headers
type UAProfile struct {
	UA       string
	Browser  string // chrome | edge | android-chrome | firefox | safari | safari-ios | cli
	CHUA     string // Sec-CH-UA value (Chromium client hints)
	Mobile   string // Sec-CH-UA-Mobile value
	Platform string // Sec-CH-UA-Platform value
}

var UAProfiles = []UAProfile{
	{UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		Browser: "chrome", CHUA: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`, Mobile: "?0", Platform: `"Windows"`},
	{UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
		Browser: "edge", CHUA: `"Microsoft Edge";v="130", "Chromium";v="130", "Not=A?_Brand";v="24"`, Mobile: "?0", Platform: `"Windows"`},
	{UA: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		Browser: "chrome", CHUA: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`, Mobile: "?0", Platform: `"macOS"`},
	{UA: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		Browser: "chrome", CHUA: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`, Mobile: "?0", Platform: `"Linux"`},
	{UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0", Browser: "firefox"},
	{UA: "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0", Browser: "firefox"},
	{UA: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15", Browser: "safari"},
	{UA: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1", Browser: "safari-ios"},
	{UA: "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		Browser: "android-chrome", CHUA: `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`, Mobile: "?1", Platform: `"Android"`},
	{UA: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		Browser: "android-chrome", CHUA: `"Google Chrome";v="130", "Chromium";v="130", "Not_A Brand";v="24"`, Mobile: "?1", Platform: `"Android"`},
	// non-browser agents (how scripts/tools commonly fetch files)
	{UA: "curl/8.11.1", Browser: "cli"},
	{UA: "Wget/1.24.5", Browser: "cli"},
	{UA: "python-requests/2.32.3", Browser: "cli"},
}

var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"de-DE,de;q=0.9,en;q=0.7",
	"fr-FR,fr;q=0.9,en;q=0.7",
	"es-ES,es;q=0.9,en;q=0.7",
	"hi-IN,hi;q=0.9,en;q=0.7",
	"tr-TR,tr;q=0.9,en;q=0.7",
	"ru-RU,ru;q=0.9,en;q=0.7",
}

// Apply builds a realistic request header set matched to the chosen UA:
// Chromium-family UAs get client hints, browsers of all kinds get Sec-Fetch-*
// and a natural Accept-Language, CLI tools send their own bare style.
func Apply(req *http.Request, randomUA bool, spoofIP bool) {
	if !randomUA {
		req.Header.Set("User-Agent", "z1pfd/1.2 (+https://github.com/Baba01hacker666/z1pfd)")
		req.Header.Set("Accept", "*/*")
	} else {
		p := UAProfiles[rand.Intn(len(UAProfiles))]
		req.Header.Set("User-Agent", p.UA)
		req.Header.Set("Accept", "*/*")

		switch p.Browser {
		case "chrome", "edge", "android-chrome":
			req.Header.Set("Sec-CH-UA", p.CHUA)
			req.Header.Set("Sec-CH-UA-Mobile", p.Mobile)
			req.Header.Set("Sec-CH-UA-Platform", p.Platform)
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
		case "firefox":
			req.Header.Set("Sec-Fetch-Site", "none")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Dest", "document")
			req.Header.Set("Sec-Fetch-User", "?1")
			req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
		case "safari", "safari-ios":
			req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
		}
	}

	// optional WAF-bypass header spoofing (off by default: keep requests realistic)
	if spoofIP {
		req.Header.Set("X-Forwarded-For", RandomIP())
		req.Header.Set("X-Real-IP", RandomIP())
		req.Header.Set("X-Originating-IP", RandomIP())
	}
}

// WAFSig describes one WAF product's fingerprint
type WAFSig struct {
	Name    string
	Headers []string // matched against lowercased "key: value" header lines
	Body    []string // matched against lowercased response body snippet
}

var WAFSignatures = []WAFSig{
	{Name: "Cloudflare", Headers: []string{"cf-ray", "cf-mitigated:", "server: cloudflare"}, Body: []string{"attention required", "checking your browser"}},
	{Name: "ModSecurity", Headers: []string{"mod_security", "modsecurity"}, Body: []string{"this error was generated by mod_security", "mod_security"}},
	{Name: "Imunify360", Headers: []string{"x-imunify"}, Body: []string{"imunify"}},
	{Name: "Sucuri CloudProxy", Headers: []string{"x-sucuri-id", "x-sucuri-cache"}, Body: []string{"sucuri website firewall"}},
	{Name: "AWS WAF", Headers: []string{"x-amzn-waf-id"}, Body: []string{"aws waf"}},
	{Name: "Akamai", Headers: []string{"x-akamai-transformed", "x-check-cachekey"}, Body: []string{"akamai"}},
	{Name: "Imperva Incapsula", Headers: []string{"x-iinfo", "x-cdn: incumbent"}, Body: []string{"incapsula", "imperva"}},
	{Name: "F5 BIG-IP", Headers: []string{"x-wa-info"}, Body: []string{"big-ip", "the request reached a web server at"}},
	{Name: "Barracuda", Headers: []string{"barra_counter_session"}, Body: []string{"barracuda"}},
	{Name: "Citrix NetScaler", Headers: []string{}, Body: []string{"netscaler"}},
	{Name: "Wordfence", Headers: []string{}, Body: []string{"wordfence", "your access to this site has been limited"}},
	{Name: "Naxsi", Headers: []string{"x-naxsi-sig"}, Body: []string{"naxsi"}},
	{Name: "DDoS-Guard", Headers: []string{"x-ddos-guard"}, Body: []string{"ddos-guard"}},
	{Name: "SafeLine", Headers: []string{"x-5m-mix"}, Body: []string{"safeline"}},
	{Name: "Cerber", Headers: []string{}, Body: []string{"cerber security"}},
}

// DetectWAF matches a 403/429 response against known WAF fingerprints
func DetectWAF(h http.Header, body string) string {
	headerLines := ""
	for k, vs := range h {
		lk := strings.ToLower(k)
		for _, v := range vs {
			headerLines += lk + ": " + strings.ToLower(v) + "\n"
		}
	}
	lb := strings.ToLower(body)

	for _, sig := range WAFSignatures {
		for _, hs := range sig.Headers {
			if strings.Contains(headerLines, hs) {
				return sig.Name
			}
		}
		for _, bs := range sig.Body {
			if strings.Contains(lb, bs) {
				return sig.Name
			}
		}
	}
	return ""
}

func RandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223)+1, rand.Intn(254)+1,
		rand.Intn(254)+1, rand.Intn(254)+1)
}

// BuildClient creates a general-purpose client (used by the extractor)
func BuildClient(timeout time.Duration, proxy string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}
