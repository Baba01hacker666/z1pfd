package extractor

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Baba01hacker666/z1pfd/internal/httpx"
)

// Intel holds extracted intelligence from the target
type Intel struct {
	Domain    string
	Subdomain string
	Keywords  []string
	Paths     []string
	Framework string
	Title     string
}

var (
	reTitle     = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	reMeta      = regexp.MustCompile(`(?i)<meta[^>]+(?:name|property)=["']([^"']+)["'][^>]+content=["']([^"']+)["']`)
	reJS        = regexp.MustCompile(`(?i)src=["']([^"']+\.js[^"']*)["']`)
	reHref      = regexp.MustCompile(`(?i)href=["']([^"'#?]+)["']`)
	reAction    = regexp.MustCompile(`(?i)action=["']([^"']+)["']`)
	reWordClean = regexp.MustCompile(`[^a-zA-Z0-9\-_]+`)
	reWordSplit = regexp.MustCompile(`[\s\-_/\.]+`)

	frameworks = map[string][]string{
		"Laravel":     {"laravel", "csrf-token", "csrf_token", "laravel_session"},
		"WordPress":   {"wp-content", "wp-includes", "wordpress"},
		"Django":      {"csrfmiddlewaretoken", "django"},
		"Rails":       {"rails", "authenticity_token"},
		"Symfony":     {"symfony", "_csrf_token"},
		"CodeIgniter": {"codeigniter", "ci_session"},
		"Drupal":      {"drupal", "drupal.js"},
		"Joomla":      {"joomla", "/components/com_"},
	}

	stopWords = map[string]bool{
		"the": true, "and": true, "for": true, "with": true,
		"this": true, "that": true, "from": true, "have": true,
		"not": true, "but": true, "are": true, "your": true,
		"all": true, "can": true, "her": true, "was": true,
		"one": true, "our": true, "out": true, "day": true,
		"get": true, "has": true, "him": true, "his": true,
		"how": true, "its": true, "may": true, "new": true,
		"now": true, "old": true, "see": true, "two": true,
		"way": true, "who": true, "boy": true, "did": true,
		"does": true, "use": true, "she": true, "each": true,
		"com": true, "www": true, "http": true, "https": true,
		"html": true, "php": true, "asp": true,
	}
)

// Extract pulls intelligence from the target URL
func Extract(target string, timeout time.Duration, proxy string) (*Intel, error) {
	intel := &Intel{
		Keywords: []string{},
		Paths:    []string{},
	}

	// parse domain/subdomain
	u, err := url.Parse(target)
	if err != nil {
		return intel, fmt.Errorf("invalid URL: %w", err)
	}

	host := u.Hostname()
	parts := strings.Split(host, ".")

	if len(parts) >= 2 {
		// domain = last two parts
		intel.Domain = strings.Join(parts[len(parts)-2:], ".")
		// strip TLD for keyword
		intel.Keywords = appendUnique(intel.Keywords, strings.ToLower(parts[len(parts)-2]))
		// subdomain
		if len(parts) > 2 {
			intel.Subdomain = strings.Join(parts[:len(parts)-2], ".")
			for _, p := range parts[:len(parts)-2] {
				if len(p) > 2 {
					intel.Keywords = appendUnique(intel.Keywords, strings.ToLower(p))
				}
			}
		}
	} else {
		intel.Domain = host
		intel.Keywords = appendUnique(intel.Keywords, host)
	}

	// fetch page (retries once if a WAF/rate-limiter gets in the way)
	client := httpx.BuildClient(timeout, proxy)
	body, err := fetchPage(client, target)
	if err != nil {
		return intel, fmt.Errorf("fetch failed: %w", err)
	}

	content := string(body)
	lower := strings.ToLower(content)

	// title
	if m := reTitle.FindStringSubmatch(content); len(m) > 1 {
		intel.Title = strings.TrimSpace(m[1])
		for _, kw := range extractWords(intel.Title) {
			intel.Keywords = appendUnique(intel.Keywords, kw)
		}
	}

	// meta tags
	for _, m := range reMeta.FindAllStringSubmatch(content, -1) {
		if len(m) > 2 {
			for _, kw := range extractWords(m[2]) {
				intel.Keywords = appendUnique(intel.Keywords, kw)
			}
		}
	}

	// JS file names → extract base names as keywords
	for _, m := range reJS.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			jsPath := m[1]
			// extract filename without ext
			segments := strings.Split(jsPath, "/")
			fname := segments[len(segments)-1]
			base := strings.Split(fname, ".")[0]
			// strip hashes (8+ hex chars)
			reHash := regexp.MustCompile(`^[a-f0-9]{8,}$`)
			if !reHash.MatchString(base) && len(base) > 2 {
				for _, kw := range extractWords(base) {
					intel.Keywords = appendUnique(intel.Keywords, kw)
				}
			}
		}
	}

	// paths from hrefs and actions
	pathSet := map[string]bool{}
	for _, m := range reHref.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			p := normalizePath(m[1], target)
			if p != "" {
				pathSet[p] = true
			}
		}
	}
	for _, m := range reAction.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			p := normalizePath(m[1], target)
			if p != "" {
				pathSet[p] = true
			}
		}
	}
	for p := range pathSet {
		intel.Paths = append(intel.Paths, p)
		// extract path segments as keywords
		segments := strings.Split(p, "/")
		for _, seg := range segments {
			seg = strings.Split(seg, ".")[0]
			if len(seg) > 2 {
				for _, kw := range extractWords(seg) {
					intel.Keywords = appendUnique(intel.Keywords, kw)
				}
			}
		}
	}

	// detect framework
	for fw, indicators := range frameworks {
		for _, ind := range indicators {
			if strings.Contains(lower, ind) {
				intel.Framework = fw
				intel.Keywords = appendUnique(intel.Keywords, strings.ToLower(fw))
				break
			}
		}
		if intel.Framework != "" {
			break
		}
	}

	// detect git exposure
	if checkGit(client, target) {
		intel.Keywords = appendUnique(intel.Keywords, "git", "repo", "source")
		intel.Paths = append(intel.Paths, "/.git/")
	}

	return intel, nil
}

func checkGit(client *http.Client, target string) bool {
	req, err := http.NewRequest("HEAD", target+"/.git/HEAD", nil)
	if err != nil {
		return false
	}
	// use a realistic UA so the probe blends in with normal browsing
	httpx.Apply(req, true, false)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// fetchPage downloads the target page, retrying a couple of times when a
// WAF/rate-limiter blocks the attempt (common on Cloudflare/Imunify360/
// ModSecurity sites) — everything downstream depends on this intelligence
func fetchPage(client *http.Client, target string) ([]byte, error) {
	var lastErr error
	backoffs := []time.Duration{0, 1500 * time.Millisecond, 3 * time.Second}
	for _, wait := range backoffs {
		if wait > 0 {
			time.Sleep(wait)
		}
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			return nil, err
		}
		httpx.Apply(req, true, false)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode == 403 {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
		resp.Body.Close()
		return body, err
	}
	return nil, lastErr
}

func extractWords(s string) []string {
	s = reWordClean.ReplaceAllString(s, " ")
	parts := reWordSplit.Split(s, -1)
	var out []string
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) >= 3 && len(p) <= 30 && !stopWords[p] {
			out = append(out, p)
		}
	}
	return out
}

func normalizePath(href, base string) string {
	if href == "" || href == "/" || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "javascript:") {
		return ""
	}

	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		u1, err := url.Parse(href)
		if err != nil {
			return ""
		}
		u2, err := url.Parse(base)
		if err != nil {
			return ""
		}
		if u1.Hostname() != u2.Hostname() {
			return ""
		}
		href = u1.Path
	}

	// extract directory portion
	if strings.Contains(href, ".") {
		// file — get directory
		parts := strings.Split(href, "/")
		if len(parts) > 1 {
			href = strings.Join(parts[:len(parts)-1], "/") + "/"
		}
	}

	if !strings.HasPrefix(href, "/") {
		href = "/" + href
	}
	if !strings.HasSuffix(href, "/") {
		href += "/"
	}

	// skip very long or suspicious paths
	if len(href) > 100 || strings.Count(href, "/") > 8 {
		return ""
	}

	return href
}

func appendUnique(slice []string, items ...string) []string {
	set := make(map[string]bool)
	for _, s := range slice {
		set[s] = true
	}
	for _, item := range items {
		if !set[item] && item != "" {
			set[item] = true
			slice = append(slice, item)
		}
	}
	return slice
}
