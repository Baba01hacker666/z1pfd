# Design: List Support for z1pfd

## Goal
Enable `z1pfd` to process multiple target URLs provided in a list file, scanning them in parallel while managing resources through a target concurrency limit.

## Requirements
- Support a new CLI flag `-l` to specify a file containing target URLs (one per line).
- Support a new CLI flag `-tc` to control how many targets are scanned simultaneously.
- Results from all targets should be aggregated into a single output file if `-o` is provided.
- Maintain the existing `-u` flag for single target scans.
- Each target scan should still utilize the `-c` concurrency for its own internal probing.

## Architecture & Implementation

### 1. CLI Flags
- `listFile` (`-l`): String, path to the input file.
- `targetConcurrency` (`-tc`): Int, default 5.

### 2. Orchestration Refactoring
- Extract the core scanning logic from `main()` into a reusable function:
  `func scanTarget(url string, cfg *scanner.Config, printer *output.Printer) []scanner.Result`
- This function will execute Phase 1 (Extraction) through Phase 5 (Scanning).

### 3. Parallel Execution Logic
- If `-l` is provided:
  1. Read and parse the file into a list of URLs.
  2. Use a `sync.WaitGroup` to track completion.
  3. Use a semaphore (buffered channel) to limit active `scanTarget` goroutines to `-tc`.
  4. Launch a goroutine for each URL.
- If `-u` is provided, it behaves as a single-item list.

### 4. Data Aggregation
- Use a `sync.Mutex` to protect a shared `[]scanner.Result` slice.
- Each `scanTarget` goroutine will append its results to this shared slice upon completion.
- Alternatively, use a results channel that a separate goroutine drains into a slice.

### 5. Output
- After all targets are processed and the `WaitGroup` is done, call `output.Save` with the aggregated results.

## Error Handling
- Invalid URLs in the list should be reported but not stop the entire process.
- File read errors for the list file should be fatal at startup.

## Testing Strategy
- Create a mock list file with 2-3 local or test URLs.
- Verify that `-tc` limits the number of concurrent scans (can be observed via verbose logging).
- Verify that results from multiple targets appear in the final output.
