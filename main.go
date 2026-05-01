package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
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
	fmt.Println(banner)

	var (
		target      = flag.String("u", "", "Target URL (required)")
		concurrency = flag.Int("c", 50, "Concurrent workers")
		timeout     = flag.Int("timeout", 10, "Request timeout in seconds")
		outputFile  = flag.String("o", "", "Output file (json/txt based on extension)")
		wordlist    = flag.String("w", "", "Custom wordlist file (one word per line)")
		extensions  = flag.String("ext", ".zip,.tar.gz,.rar,.7z", "Comma-separated extensions")
		proxy       = flag.String("proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080)")
		depth       = flag.Int("depth", 1, "Path depth (1=root paths, 2=sub paths)")
		noRedirect  = flag.Bool("no-redirect", false, "Do not follow redirects")
		randomUA    = flag.Bool("rand-ua", true, "Randomize User-Agent")
		minSize     = flag.Int64("min-size", 0, "Minimum file size in bytes to report")
		resume      = flag.String("resume", "", "Resume file path (saves/loads progress)")
		rateLimit   = flag.Int("rate", 0, "Requests per second limit (0=unlimited)")
		verbose     = flag.Bool("v", false, "Verbose output")
		noColor     = flag.Bool("no-color", false, "Disable colored output")
	)

	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "[ERR] -u target URL is required")
		flag.Usage()
		os.Exit(1)
	}

	// normalize target
	if !strings.HasPrefix(*target, "http://") && !strings.HasPrefix(*target, "https://") {
		*target = "https://" + *target
	}
	*target = strings.TrimRight(*target, "/")

	exts := strings.Split(*extensions, ",")

	cfg := &scanner.Config{
		Target:      *target,
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
	}

	printer := output.New(!*noColor)
	printer.Info("Target  : %s", *target)
	printer.Info("Workers : %d", *concurrency)
	printer.Info("Timeout : %ds", *timeout)
	printer.Info("Exts    : %s", *extensions)

	// Phase 1: intelligence extraction
	printer.Section("PHASE 1 — Intelligence Extraction")
	intel, err := extractor.Extract(*target, time.Duration(*timeout)*time.Second, *proxy)
	if err != nil {
		printer.Warn("Extraction partial: %v", err)
	}
	printer.Info("Keywords found: %d", len(intel.Keywords))
	printer.Info("Paths found   : %d", len(intel.Paths))
	printer.Info("Framework     : %s", intel.Framework)

	// Phase 2+3: wordlist generation + mutation
	printer.Section("PHASE 2/3 — Generating & Mutating Wordlist")
	gen := generator.New(intel, exts)

	var baseWords []string
	if *wordlist != "" {
		baseWords, err = generator.LoadWordlist(*wordlist)
		if err != nil {
			printer.Warn("Failed to load wordlist: %v — using generated only", err)
		} else {
			printer.Info("Custom wordlist: %d words loaded", len(baseWords))
		}
	}

	candidates := gen.Generate(baseWords)
	printer.Info("Candidates    : %d filenames generated", len(candidates))

	// Phase 4: path expansion
	printer.Section("PHASE 4 — Expanding Paths")
	paths := generator.ExpandPaths(candidates, intel.Paths, *depth)
	printer.Info("Total probes  : %d URLs to test", len(paths))

	// Phase 5: scanning
	printer.Section("PHASE 5 — Scanning")
	startTime := time.Now()

	results := scanner.Run(cfg, paths, printer)

	elapsed := time.Since(startTime)
	printer.Section("RESULTS")
	printer.Info("Scanned in %s | Found: %d", elapsed.Round(time.Millisecond), len(results))

	for _, r := range results {
		printer.Found(r)
	}

	// Phase 6: output
	if *outputFile != "" && len(results) > 0 {
		printer.Section("PHASE 6 — Exporting")
		if err := output.Save(*outputFile, results); err != nil {
			printer.Warn("Failed to save output: %v", err)
		} else {
			printer.Info("Results saved to: %s", *outputFile)
		}
	}

	if len(results) == 0 {
		printer.Warn("No exposed archives found.")
	}
}
