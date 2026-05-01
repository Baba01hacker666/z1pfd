# z1pfd — Dynamic ZIP Finder
**by Baba01hacker666 | Doraemon Cyber Team**

---

## Build

```bash
cd z1pfd
go mod tidy    # no external deps, this is basically a no-op
go build -ldflags="-s -w" -o z1pfd .
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
  -u string        Target URL (required)
  -c int           Concurrency / workers (default: 50)
  -timeout int     Request timeout in seconds (default: 10)
  -o string        Output file (.json or .txt)
  -w string        Custom wordlist file
  -ext string      Extensions (default: .zip,.tar.gz,.rar,.7z)
  -proxy string    HTTP proxy (e.g. http://127.0.0.1:8080)
  -depth int       Path depth 1=root, 2=nested (default: 1)
  -no-redirect     Don't follow redirects
  -rand-ua         Randomize User-Agent (default: true)
  -min-size int    Minimum file size to report (bytes)
  -resume string   Resume file path (saves progress)
  -rate int        Requests per second limit (0=unlimited)
  -v               Verbose output
  -no-color        Disable ANSI colors
```

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

# Resume interrupted scan
./z1pfd -u https://target.com -c 150 -resume state.txt

# Rate-limited scan (bypass WAF)
./z1pfd -u https://target.com -rate 10 -rand-ua
```

---

## Architecture

```
z1pfd/
├── main.go                    # CLI entrypoint, phase orchestration
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
[Scanner]    ──→  goroutine pool → HEAD+GET probes → magic byte check
    │
    ▼
[Output]     ──→  CLI + JSON/TXT export
```

### Detection Logic

1. HTTP 200 / 206 status
2. Content-Type matches archive MIME types
3. Magic bytes: PK\x03\x04 (ZIP), Rar!, 7z, \x1F\x8B (gzip)
4. Content-Length > threshold
5. Extension match + non-zero body

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

*DCT — Doraemon Cyber Team | github.com/doraemoncyberteam*
