package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Baba01hacker666/z1pfd/internal/extractor"
	"github.com/Baba01hacker666/z1pfd/internal/generator"
	"github.com/Baba01hacker666/z1pfd/internal/output"
	"github.com/Baba01hacker666/z1pfd/internal/scanner"
)

const banner = `
 ______  __  ____  ____  ____
|_  /  ||  ||  _ \|  __||  _ \
  / / _ | || |_) || |_  | | | |
 /_/|___||_||____/|____||_|_|_|

  Dynamic ZIP Finder v1.1
  by Baba01hacker666 | DCT
`

type ToolConfig struct {
	Concurrency       int    `yaml:"concurrency"`
	TargetConcurrency int    `yaml:"target_concurrency"`
	Timeout           int    `yaml:"timeout"`
	Extensions        string `yaml:"extensions"`
	Proxy             string `yaml:"proxy"`
	Depth             int    `yaml:"depth"`
	NoRedirect        *bool  `yaml:"no_redirect"`
	RandomUA          *bool  `yaml:"rand_ua"`
	MinSize           int64  `yaml:"min_size"`
	RateLimit         int    `yaml:"rate_limit"`
	Wordlist          string `yaml:"wordlist"`
	Quick             *bool  `yaml:"quick"`
}

func loadConfig(path string) (*ToolConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ToolConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func main() {
	fmt.Print(banner)

	var (
		target            = flag.String("u", "", "Target URL")
		listFile          = flag.String("l", "", "File containing target URLs (one per line)")
		concurrency       = flag.Int("c", 50, "Concurrent workers")
		targetConcurrency = flag.Int("tc", 5, "Maximum concurrent targets")
		timeout           = flag.Int("timeout", 10, "Request timeout in seconds")
		outputFile        = flag.String("o", "", "Output file (json/txt based on extension)")
		wordlist          = flag.String("w", "", "Custom wordlist file (one word per line)")
		extensions        = flag.String("ext", ".zip", "Comma-separated extensions")
		proxy             = flag.String("proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080)")
		depth             = flag.Int("depth", 1, "Path depth (1=root paths, 2=sub paths)")
		noRedirect        = flag.Bool("no-redirect", false, "Do not follow redirects")
		randomUA          = flag.Bool("rand-ua", true, "Randomize User-Agent")
		minSize           = flag.Int64("min-size", 0, "Minimum file size in bytes to report")
		resume            = flag.String("resume", "", "Resume file path (saves/loads progress)")
		rateLimit         = flag.Int("rate", 0, "Requests per second limit (0=unlimited)")
		verbose           = flag.Bool("v", false, "Verbose output")
		noColor           = flag.Bool("no-color", false, "Disable colored output")
		quick             = flag.Bool("q", false, "Quick mode: limit paths and words for fast testing")
		configFile        = flag.String("config", "", "Path to YAML config file")
	)

	flag.Parse()

	// YAML config values apply only to flags NOT explicitly set on the command
	// line, so the CLI always wins and YAML never overrides user intent.
	if *configFile != "" {
		cfg, err := loadConfig(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] Failed to load config file: %v\n", err)
			os.Exit(1)
		}

		explicit := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
		apply := func(name string, fn func()) {
			if !explicit[name] {
				fn()
			}
		}

		apply("c", func() {
			if cfg.Concurrency > 0 {
				*concurrency = cfg.Concurrency
			}
		})
		apply("tc", func() {
			if cfg.TargetConcurrency > 0 {
				*targetConcurrency = cfg.TargetConcurrency
			}
		})
		apply("timeout", func() {
			if cfg.Timeout > 0 {
				*timeout = cfg.Timeout
			}
		})
		apply("ext", func() {
			if cfg.Extensions != "" {
				*extensions = cfg.Extensions
			}
		})
		apply("proxy", func() {
			if cfg.Proxy != "" {
				*proxy = cfg.Proxy
			}
		})
		apply("depth", func() {
			if cfg.Depth > 0 {
				*depth = cfg.Depth
			}
		})
		apply("min-size", func() {
			if cfg.MinSize > 0 {
				*minSize = cfg.MinSize
			}
		})
		apply("rate", func() {
			if cfg.RateLimit > 0 {
				*rateLimit = cfg.RateLimit
			}
		})
		apply("w", func() {
			if cfg.Wordlist != "" {
				*wordlist = cfg.Wordlist
			}
		})
		apply("q", func() {
			if cfg.Quick != nil {
				*quick = *cfg.Quick
			}
		})
		apply("no-redirect", func() {
			if cfg.NoRedirect != nil {
				*noRedirect = *cfg.NoRedirect
			}
		})
		apply("rand-ua", func() {
			if cfg.RandomUA != nil {
				*randomUA = *cfg.RandomUA
			}
		})
	}

	if *target == "" && *listFile == "" {
		fmt.Fprintln(os.Stderr, "[ERR] -u target URL or -l list file is required")
		flag.Usage()
		os.Exit(1)
	}

	// normalize extensions: trim, lowercase, dedupe, ensure leading dot
	seenExt := map[string]bool{}
	var exts []string
	for _, e := range strings.Split(*extensions, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if !seenExt[e] {
			seenExt[e] = true
			exts = append(exts, e)
		}
	}
	if len(exts) == 0 {
		fmt.Fprintln(os.Stderr, "[ERR] no valid extensions after parsing -ext")
		os.Exit(1)
	}

	// graceful shutdown: first Ctrl+C stops gracefully (saves resume state),
	// second Ctrl+C forces exit
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		fmt.Fprintln(os.Stderr, "\n[!] Interrupt — stopping gracefully, press Ctrl+C again to force exit")
		<-sigCh
		os.Exit(130)
	}()

	printer := output.New(!*noColor)

	var targets []string
	if *listFile != "" {
		f, err := os.Open(*listFile)
		if err != nil {
			printer.Warn("Failed to open list file: %v", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
	} else if *target != "" {
		targets = append(targets, strings.TrimSpace(*target))
	}

	var baseWords []string
	var err error
	if *wordlist != "" {
		baseWords, err = generator.LoadWordlist(*wordlist)
		if err != nil {
			printer.Warn("Failed to load wordlist: %v — using generated only", err)
		} else {
			printer.Info("Custom wordlist: %d words loaded", len(baseWords))
		}
	}

	multi := len(targets) > 1

	if !multi {
		printer.Info("Target  : %s", targets[0])
	} else {
		printer.Info("Targets : %d URLs loaded", len(targets))
	}
	printer.Info("Workers : %d", *concurrency)
	printer.Info("Timeout : %ds", *timeout)
	printer.Info("Exts    : %s", strings.Join(exts, ","))

	var allResults []scanner.Result
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, *targetConcurrency)

	for _, t := range targets {
		// normalize target
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			t = "https://" + t
		}
		t = strings.TrimRight(t, "/")

		cfg := &scanner.Config{
			Target:      t,
			Concurrency: *concurrency,
			Timeout:     time.Duration(*timeout) * time.Second,
			Extensions:  exts,
			Proxy:       *proxy,
			Depth:       *depth,
			NoRedirect:  *noRedirect,
			RandomUA:    *randomUA,
			MinSize:     *minSize,
			RateLimit:   *rateLimit,
			Verbose:     *verbose,
			ResumeFile:  *resume,
			NoProgress:  multi,
			Ctx:         ctx,
		}

		wg.Add(1)
		go func(targetURL string, config *scanner.Config) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := scanTarget(targetURL, config, printer, baseWords, multi, *quick)
			mu.Lock()
			allResults = append(allResults, res...)
			mu.Unlock()
		}(t, cfg)
	}

	wg.Wait()

	printer.Section("RESULTS")
	printer.Info("Found: %d total", len(allResults))

	for _, r := range allResults {
		printer.Found(r)
	}

	// Phase 6: output
	if *outputFile != "" && len(allResults) > 0 {
		printer.Section("PHASE 6 — Exporting")
		if err := output.Save(*outputFile, allResults); err != nil {
			printer.Warn("Failed to save output: %v", err)
		} else {
			printer.Info("Results saved to: %s", *outputFile)
		}
	}

	if len(allResults) == 0 {
		printer.Warn("No exposed archives found.")
	}
}

func scanTarget(url string, cfg *scanner.Config, printer *output.Printer, baseWords []string, multi bool, quick bool) []scanner.Result {
	if multi {
		printer.Info("[%s] Starting scan...", url)
	}

	// Phase 1: intelligence extraction
	if !multi {
		printer.Section("PHASE 1 — Intelligence Extraction")
	}
	intel, err := extractor.Extract(url, cfg.Timeout, cfg.Proxy)
	if err != nil {
		if !multi {
			printer.Warn("Extraction partial: %v", err)
		}
	}
	if !multi {
		printer.Info("Keywords found: %d", len(intel.Keywords))
		printer.Info("Paths found   : %d", len(intel.Paths))
		printer.Info("Framework     : %s", intel.Framework)
	}

	// Phase 2/3: Generating & Mutating Wordlist
	if !multi {
		printer.Section("PHASE 2/3 — Generating & Mutating Wordlist")
	}
	gen := generator.New(intel, cfg.Extensions)
	candidates := gen.Generate(baseWords, quick)
	if !multi {
		printer.Info("Candidates    : %d filenames generated", len(candidates))
	}

	// Phase 4: Path Expansion
	if !multi {
		printer.Section("PHASE 4 — Expanding Paths")
	}
	paths := generator.ExpandPaths(candidates, intel.Paths, cfg.Depth, quick)
	if !multi {
		printer.Info("Total probes  : %d URLs to test", len(paths))
	}

	// Phase 5: Scanning
	if !multi {
		printer.Section("PHASE 5 — Scanning")
		startTime := time.Now()
		results := scanner.Run(cfg, paths, printer)
		elapsed := time.Since(startTime)
		printer.Info("Scanned in %s | Found: %d", elapsed.Round(time.Millisecond), len(results))
		return results
	}

	// If multi, be less verbose
	results := scanner.Run(cfg, paths, printer)
	if len(results) > 0 {
		printer.Info("[%s] Found %d archives", url, len(results))
	} else {
		printer.Info("[%s] Completed. No archives found.", url)
	}
	return results
}
