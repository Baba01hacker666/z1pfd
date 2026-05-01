package generator

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"z1pfd/internal/extractor"
)

// Generator builds dynamic wordlists from intel
type Generator struct {
	intel *extractor.Intel
	exts  []string
}

var (
	commonNames = []string{
		"backup", "backups", "bak", "db", "database", "dump", "data",
		"site", "web", "www", "root", "app", "application", "src", "source",
		"files", "file", "upload", "uploads", "media", "assets", "static",
		"config", "configs", "conf", "settings", "env", "environment",
		"admin", "portal", "dashboard", "panel", "cp", "control",
		"old", "new", "temp", "tmp", "archive", "archives",
		"export", "exports", "import", "imports",
		"public", "private", "internal", "external",
		"release", "releases", "dist", "build",
		"logs", "log", "audit",
		"sql", "mysql", "postgres", "mongo", "redis",
		"dev", "development", "staging", "prod", "production", "test", "testing", "uat",
		"www-data", "htdocs", "httpdocs", "html", "public_html",
		"store", "shop", "api", "backend", "frontend",
	}

	prefixes = []string{
		"backup_", "old_", "dev_", "prod_", "test_", "new_",
		"copy_", "archive_", "bak_", "export_",
	}

	suffixes = []string{
		"_backup", "_old", "_final", "_v1", "_v2", "_v3",
		"_prod", "_dev", "_bak", "_copy", "_export",
		"_release", "_latest", "_new", "_archive",
		"_full", "_complete", "_all",
	}

	versions = []string{
		"v1", "v2", "v3", "v4", "final", "release", "latest", "stable",
	}

	separators = []string{"-", "_", ".", ""}

	commonPaths = []string{
		"/",
		"/backup/",
		"/backups/",
		"/bak/",
		"/admin/",
		"/uploads/",
		"/upload/",
		"/files/",
		"/file/",
		"/public/",
		"/private/",
		"/.git/",
		"/www/",
		"/old/",
		"/new/",
		"/temp/",
		"/tmp/",
		"/data/",
		"/db/",
		"/database/",
		"/export/",
		"/exports/",
		"/archive/",
		"/archives/",
		"/assets/",
		"/media/",
		"/static/",
		"/src/",
		"/source/",
		"/dist/",
		"/build/",
		"/release/",
		"/html/",
		"/htdocs/",
		"/public_html/",
		"/var/www/",
		"/home/",
		"/store/",
		"/logs/",
		"/log/",
		"/api/",
		"/wp-content/",
		"/storage/",
		"/app/storage/",
	}
)

// New creates a Generator
func New(intel *extractor.Intel, exts []string) *Generator {
	return &Generator{intel: intel, exts: exts}
}

// Generate produces all candidate filenames (without paths)
func (g *Generator) Generate(customWords []string) []string {
	seen := make(map[string]bool)
	var words []string

	addWord := func(w string) {
		w = strings.ToLower(w)
		if !seen[w] && w != "" {
			seen[w] = true
			words = append(words, w)
		}
	}

	// collect base words
	bases := collectBases(g.intel)
	for _, w := range customWords {
		bases = append(bases, strings.TrimSpace(w))
	}

	years := generateYears()
	dates := generateDates()

	for _, base := range bases {
		if base == "" {
			continue
		}
		base = strings.ToLower(base)

		// plain
		addWord(base)

		// with prefixes
		for _, pfx := range prefixes {
			addWord(pfx + base)
		}

		// with suffixes
		for _, sfx := range suffixes {
			addWord(base + sfx)
		}

		// with versions
		for _, sep := range separators {
			for _, ver := range versions {
				addWord(base + sep + ver)
				addWord(ver + sep + base)
			}
		}

		// with years
		for _, sep := range separators {
			for _, yr := range years {
				addWord(base + sep + yr)
				addWord(yr + sep + base)
			}
		}

		// with dates
		for _, sep := range []string{"_", "-", ""} {
			for _, dt := range dates {
				addWord(base + sep + dt)
			}
		}

		// prefix + base + year
		for _, pfx := range prefixes {
			for _, yr := range years {
				for _, sep := range separators {
					addWord(pfx + base + sep + yr)
				}
			}
		}

		// common combos
		for _, cn := range commonNames {
			for _, sep := range []string{"_", "-"} {
				addWord(base + sep + cn)
				addWord(cn + sep + base)
			}
		}

		// uppercase / capitalized variants (generates filenames like Backup, BACKUP)
		addWord(strings.ToUpper(base))
		addWord(strings.Title(strings.ToLower(base)))
	}

	// add all common names standalone + date combos
	for _, cn := range commonNames {
		addWord(cn)
		for _, yr := range years {
			for _, sep := range separators {
				addWord(cn + sep + yr)
			}
		}
		for _, sfx := range suffixes {
			addWord(cn + sfx)
		}
	}

	// add timestamped variants
	for _, base := range bases {
		if base == "" {
			continue
		}
		ts := fmt.Sprintf("%d", time.Now().Unix())
		addWord(base + "_" + ts[:6]) // partial epoch
	}

	// apply extensions
	var result []string
	for _, word := range words {
		for _, ext := range g.exts {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			result = append(result, word+ext)
		}
	}

	return result
}

func collectBases(intel *extractor.Intel) []string {
	var bases []string
	set := make(map[string]bool)

	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !set[s] {
			set[s] = true
			bases = append(bases, s)
		}
	}

	// domain-based
	if intel.Domain != "" {
		add(intel.Domain)
		// strip TLD
		parts := strings.Split(intel.Domain, ".")
		if len(parts) >= 1 {
			add(parts[0])
		}
		// hyphenated version
		add(strings.ReplaceAll(intel.Domain, ".", "-"))
		add(strings.ReplaceAll(intel.Domain, ".", "_"))
	}

	// subdomain
	if intel.Subdomain != "" && intel.Subdomain != "www" {
		add(intel.Subdomain)
		for _, p := range strings.Split(intel.Subdomain, ".") {
			add(p)
		}
	}

	// framework name
	if intel.Framework != "" {
		add(strings.ToLower(intel.Framework))
	}

	// keywords from intel
	for _, kw := range intel.Keywords {
		add(kw)
	}

	return bases
}

// ExpandPaths combines filenames with paths to build full URL sets
func ExpandPaths(filenames []string, extractedPaths []string, depth int) []string {
	// merge extracted paths with common paths
	pathSet := make(map[string]bool)
	for _, p := range commonPaths {
		pathSet[p] = true
	}
	for _, p := range extractedPaths {
		if len(p) < 60 { // skip very long paths
			pathSet[p] = true
		}
	}

	var paths []string
	for p := range pathSet {
		paths = append(paths, p)
	}

	// depth > 1: generate sub-path combinations
	if depth > 1 {
		var extended []string
		for _, p1 := range paths {
			for _, p2 := range commonPaths {
				combined := strings.TrimRight(p1, "/") + p2
				if combined != p1 {
					extended = append(extended, combined)
				}
			}
		}
		paths = append(paths, extended...)
	}

	// deduplicate paths
	pathSet = make(map[string]bool)
	for _, p := range paths {
		pathSet[p] = true
	}

	// build URL list
	seen := make(map[string]bool)
	var result []string

	for path := range pathSet {
		for _, fname := range filenames {
			url := path + fname
			if !seen[url] {
				seen[url] = true
				result = append(result, url)
			}
		}
	}

	return result
}

// LoadWordlist reads words from a file
func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, scanner.Err()
}

func generateYears() []string {
	now := time.Now()
	var years []string
	for y := now.Year() - 4; y <= now.Year()+1; y++ {
		years = append(years, fmt.Sprintf("%d", y))
		// short year
		years = append(years, fmt.Sprintf("%02d", y%100))
	}
	return years
}

func generateDates() []string {
	now := time.Now()
	var dates []string

	for delta := 0; delta <= 365*3; delta += 30 {
		t := now.AddDate(0, 0, -delta)
		dates = append(dates,
			t.Format("20060102"),          // YYYYMMDD
			t.Format("2006-01-02"),         // YYYY-MM-DD
			t.Format("02-01-2006"),         // DD-MM-YYYY
			t.Format("01-2006"),            // MM-YYYY
			t.Format("2006-01"),            // YYYY-MM
			t.Format("200601"),             // YYYYMM
			fmt.Sprintf("%d", t.Year()),    // YYYY
		)
	}

	// deduplicate
	seen := make(map[string]bool)
	var result []string
	for _, d := range dates {
		if !seen[d] {
			seen[d] = true
			result = append(result, d)
		}
	}
	return result
}
