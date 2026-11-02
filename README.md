# z1pfd — Dynamic ZIP Finder

**by Baba01hacker666 | Doraemon Cyber Team**

z1pfd is a fast, self-contained Go tool that hunts for **exposed backup & archive files** (`zip`, `tar.gz`, `rar`, `7z`, ...) on web targets. It doesn't blindly brute-force a static list: it first *understands* the target, then builds a tailored wordlist from what it learns, and verifies every hit with HTTP status, Content-Type and **archive magic bytes** to cut false positives.

```text
 ______  __  ____  ____  ____
|_  /  ||  ||  _ \|  __||  _ \
  / / _ | || |_) || |_  | | | |
 /_/|___||_||____/|____||_|_|_|
```

> ⚠️ **Use responsibly.** Only scan systems you own or have explicit written permission to test (e.g. bug bounty scope). Unauthorized scanning is illegal in most jurisdictions. The authors are not responsible for misuse.

---

## Features

- 🧠 **Dynamic wordlist generation** — extracts keywords from the target's title, meta tags, JS filenames, link paths, subdomains and framework fingerprint, then generates thousands of tailored candidate filenames
- 🔍 **Intelligence phase** — detects Laravel, WordPress, Django, Rails, Symfony, CodeIgniter, Drupal, Joomla and open `.git/` exposure
- 🔬 **Magic-byte verification** — confirms bodies really are ZIP/RAR/7Z/GZ/BZ2 archives, filtering out soft-404 pages
- 🚀 **Concurrent HTTP probing** — tunable worker pool, HEAD-first with GET verification
- 🛑 **Graceful Ctrl+C** — stops cleanly, auto-saves partial progress every 10 s, picks up exactly where it stopped with `-resume`
- 🎛️ **Stealth & rate control** — randomized User-Agent, proxy support, per-second rate limiting, multi-target concurrency
- 📦 **Bulk scanning** — `‑l` list files, per-target concurrency cap, JSON/TXT export
- ⚙️ **YAML config files** — `‑config` with proper CLI-wins-over-config precedence
- 🪶 **Zero heavy dependencies** — single Go module, builds for Linux/Windows/macOS/Termux

---

## Build

```bash
go mod tidy
go build -ldflags="-s -w" -o z1pfd .
```

Or install straight from GitHub (Go 1.21+):

```bash
go install github.com/Baba01hacker666/z1pfd@latest
```

Cross-compile:

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o z1pfd-linux .

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o z1pfd.exe .

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o z1pfd-mac .

# Android/Termux arm64
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o z1pfd-termux .
```

---

## Usage

```
z1pfd -u https://target.com [options]

Options:
  -u string        Target URL (required unless -l)
  -l string        File containing target URLs (one per line)
  -c int           Concurrency / workers (default: 50)
  -tc int          Max targets scanned simultaneously (default: 5)
  -timeout int     Request timeout in seconds (default: 10)
  -o string        Output file (.json or .txt based on extension)
  -w string        Custom wordlist file (one word per line, # = comment)
  -ext string      Comma-separated extensions (default: .zip)
  -proxy string    HTTP proxy (e.g. http://127.0.0.1:8080)
  -depth int       Path depth 1=common root paths, 2=expanded sub-paths (default: 1)
  -no-redirect     Don't follow redirects
  -rand-ua         Randomize User-Agent (default: true)
  -min-size int    Minimum file size in bytes to report
  -resume string   Resume file path (auto-saves progress every 10 s)
  -rate int        Requests per second limit (0=unlimited)
  -q               Quick mode: limited paths & mutations for fast testing
  -config string   YAML config file (see config.example.yaml)
  -v               Verbose output
  -no-color        Disable ANSI colors
```

### YAML config

```yaml
# config.yaml — CLI flags always override values from this file
concurrency: 100
timeout: 8
extensions: ".zip,.tar.gz,.rar,.7z"
depth: 1
min_size: 100000
rate_limit: 20
quick: false
```

```bash
z1pfd -u https://target.com -config config.yaml
```

See [`config.example.yaml`](config.example.yaml) for all options.

---

## Examples

```bash
# Basic scan
./z1pfd -u https://target.com

# High-speed with output
./z1pfd -u https://target.com -c 200 -timeout 5 -o results.json

# With proxy (Burp)
./z1pfd -u https://target.com -c 50 -proxy http://127.0.0.1:8080 -o hits.json

# Custom extensions + custom wordlist
./z1pfd -u https://target.com -ext .zip,.gz,.bak -w mywords.txt

# Deep path scan
./z1pfd -u https://target.com -depth 2 -c 100

# Bulk scan a target list
./z1pfd -l targets.txt -tc 5 -o hits.json

# Interrupt, resume later — progress auto-saved
./z1pfd -u https://target.com -resume state.txt        # Ctrl+C any time
./z1pfd -u https://target.com -resume state.txt        # continues where it left off

# Rate-limited scan (WAF-friendly)
./z1pfd -u https://target.com -rate 10 -rand-ua

# Fast test run
./z1pfd -u https://target.com -q
```

---

## Architecture

```
z1pfd/
├── main.go                    # CLI entrypoint, phase orchestration, signal handling
├── config.example.yaml        # annotated YAML config sample
└── internal/
    ├── extractor/
    │   └── extractor.go       # Phase 1: intelligence extraction
    ├── generator/
    │   └── generator.go       # Phase 2+3: wordlist gen + mutation engine
    ├── scanner/
    │   └── scanner.go         # Phase 5: concurrent HTTP probe engine
    └── output/
        └── output.go          # Phase 6: colored output + JSON/TXT export
```

### Pipeline

```
Target URL
    │
    ▼
[Extractor]  ──→  domain, subdomain, title, keywords, paths, framework
    │
    ▼
[Generator]  ──→  base words + mutations + dates + versions + separators
    │
    ▼
[Path Expander] ─→ 40+ common paths × N filenames = candidate URLs
    │
    ▼
[Scanner]    ──→  goroutine pool → HEAD→GET probes → magic byte check
    │
    ▼
[Output]     ──→  CLI + JSON/TXT export
```

### Detection Logic

1. HTTP 200 / 206 status
2. Content-Type matches archive MIME types (text content is rejected — blocks soft-404 pages)
3. Magic bytes: `PK\x03\x04` (ZIP), `Rar!`, `7z`, `\x1F\x8B` (gzip), `BZh` (bzip2)
4. Content-Length checks
5. Extension match; HEAD "hits" are re-confirmed with a GET before reporting

### Mutation Engine

Given base word `example`:
- Prefixes: `backup_example`, `old_example`, `dev_example` ...
- Suffixes: `example_backup`, `example_v1`, `example_prod` ...
- Versions: `example-v1`, `example_final` ...
- Years: `example_2024`, `example-2023` ...
- Dates: `example_20240101`, `example-2024-01` ...
- Combined: `backup_example_2024` ...
- Cross: `example_database`, `database_example` ...

---

## Output Format

```
[*] Target  : https://example.com
[*] Workers : 50
[*] Timeout : 10s

◈ PHASE 1 — Intelligence Extraction
[*] Keywords found: 12
[*] Framework     : Laravel

◈ PHASE 2/3 — Generating & Mutating Wordlist
[*] Candidates    : 14,832 filenames generated

◈ PHASE 5 — Scanning
[SCAN] [████████████░░░░░░░░░░░░░░░░░░] 6000/14832 (40.4%) | Found: 2

◈ RESULTS
[FOUND] https://example.com/backup_2024.zip (200) [12.4MB] [143ms] [MAGIC✓]
[FOUND] https://example.com/backup/example-prod.tar.gz (200) [8.2MB] [201ms]
```

---

*DCT — Doraemon Cyber Team*
