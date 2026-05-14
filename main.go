package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"z1pfd/internal/extractor"
	"z1pfd/internal/generator"
	"z1pfd/internal/output"
	"z1pfd/internal/scanner"
)

const banner = `
 ______  __  ____  ____  ____
|_  /  ||  ||  _ \|  __||  _ \
  / / _ | || |_) || |_  | | | |
 /_/|___||_||____/|____||_|_|_|

  Dynamic ZIP Finder v1.0
  by Baba01hacker666 | DCT
`

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
		extensions        = flag.String("ext", ".zip,.tar.gz,.rar,.7z", "Comma-separated extensions")
		proxy             = flag.String("proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080)")
		depth             = flag.Int("depth", 1, "Path depth (1=root paths, 2=sub paths)")
		noRedirect        = flag.Bool("no-redirect", false, "Do not follow redirects")
		randomUA          = flag.Bool("rand-ua", true, "Randomize User-Agent")
		minSize           = flag.Int64("min-size", 0, "Minimum file size in bytes to report")
		resume            = flag.String("resume", "", "Resume file path (saves/loads progress)")
		rateLimit         = flag.Int("rate", 0, "Requests per second limit (0=unlimited)")
		verbose           = flag.Bool("v", false, "Verbose output")
		noColor           = flag.Bool("no-color", false, "Disable colored output")
	)

	flag.Parse()

	if *target == "" && *listFile == "" {
		fmt.Fprintln(os.Stderr, "[ERR] -u target URL or -l list file is required")
		flag.Usage()
		os.Exit(1)
	}

	exts := strings.Split(*extensions, ",")

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
	printer.Info("Exts    : %s", *extensions)

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
		}

		wg.Add(1)
		go func(targetURL string, config *scanner.Config) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := scanTarget(targetURL, config, printer, baseWords, multi)
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

func scanTarget(url string, cfg *scanner.Config, printer *output.Printer, baseWords []string, multi bool) []scanner.Result {
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
	candidates := gen.Generate(baseWords)
	if !multi {
		printer.Info("Candidates    : %d filenames generated", len(candidates))
	}

	// Phase 4: Path Expansion
	if !multi {
		printer.Section("PHASE 4 — Expanding Paths")
	}
	paths := generator.ExpandPaths(candidates, intel.Paths, cfg.Depth)
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
