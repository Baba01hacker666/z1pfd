# List Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add support for scanning a list of target URLs in parallel with a concurrency limit.

**Architecture:** Refactor `main.go` to support a worker pool for target URLs. Add `-l` and `-tc` flags. Use a mutex-protected slice for aggregating results. Disable progress bar when multiple targets are scanned to prevent output corruption.

**Tech Stack:** Go (Standard Library)

---

### Task 1: Refactor main.go and add new flags

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Add new flags `-l` and `-tc`**

```go
		listFile    = flag.String("l", "", "File containing target URLs (one per line)")
		targetConcurrency = flag.Int("tc", 5, "Maximum concurrent targets")
```

- [ ] **Step 2: Move scanning logic to `scanTarget` function**

Extract Phase 1 to Phase 5 into a separate function.

```go
func scanTarget(url string, cfg *scanner.Config, printer *output.Printer, baseWords []string, multi bool) []scanner.Result {
    // If multi is true, we should probably prefix output with the target URL
    // and potentially disable the progress bar in cfg if we can.
    
    // Phase 1: Extraction
    // Phase 2/3: Wordlist
    // Phase 4: Path Expansion
    // Phase 5: Scanning
    return results
}
```

- [ ] **Step 3: Implement list reading and worker pool in `main()`**

```go
    var targets []string
    if *listFile != "" {
        // Read file
    } else if *target != "" {
        targets = []string{*target}
    }
    
    // Worker pool logic with sync.WaitGroup and semaphore channel
```

- [ ] **Step 4: Aggregate results and save**

```go
    var allResults []scanner.Result
    var mu sync.Mutex
    // append results in scanTarget goroutines
```

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "feat: add list support and target concurrency flags"
```

### Task 2: Handle Multi-Target Output

**Files:**
- Modify: `internal/scanner/scanner.go`
- Modify: `internal/output/output.go`

- [ ] **Step 1: Add `QuietProgress` to `scanner.Config`**

To avoid progress bar conflicts when multiple targets are running.

```go
type Config struct {
    // ... existing ...
    QuietProgress bool
}
```

- [ ] **Step 2: Use `QuietProgress` in `scanner.Run`**

```go
	// background progress updater
	go func() {
        if cfg.QuietProgress { return }
        // ... existing ticker loop ...
    }()
```

- [ ] **Step 3: Update `scanTarget` in `main.go` to use `QuietProgress`**

Set `cfg.QuietProgress = true` if `len(targets) > 1`.

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/scanner.go main.go
git commit -m "refactor: disable progress bar in multi-target mode"
```

### Task 3: Verification

- [ ] **Step 1: Create a test list file**

```bash
echo "http://localhost:8080" > targets.txt
echo "http://localhost:8081" >> targets.txt
```

- [ ] **Step 2: Run z1pfd with -l**

```bash
./z1pfd -l targets.txt -tc 2 -o results.json
```

- [ ] **Step 3: Verify results.json contains aggregated results**

- [ ] **Step 4: Commit tests/verification notes**
