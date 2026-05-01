package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"z1pfd/internal/scanner"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// Printer handles colored terminal output
type Printer struct {
	color bool
}

// New creates a Printer
func New(color bool) *Printer {
	return &Printer{color: color}
}

func (p *Printer) colorize(color, s string) string {
	if !p.color {
		return s
	}
	return color + s + colorReset
}

func (p *Printer) Info(format string, args ...interface{}) {
	prefix := p.colorize(colorCyan, "[*]")
	fmt.Printf("%s %s\n", prefix, fmt.Sprintf(format, args...))
}

func (p *Printer) Warn(format string, args ...interface{}) {
	prefix := p.colorize(colorYellow, "[!]")
	fmt.Printf("%s %s\n", prefix, fmt.Sprintf(format, args...))
}

func (p *Printer) Section(title string) {
	bar := strings.Repeat("─", 50)
	fmt.Printf("\n%s\n%s %s\n%s\n",
		p.colorize(colorDim, bar),
		p.colorize(colorPurple+colorBold, "◈"),
		p.colorize(colorBold, title),
		p.colorize(colorDim, bar),
	)
}

func (p *Printer) Progress(done, total int64, pct float64, found int64) {
	bar := buildProgressBar(pct, 30)
	fmt.Printf("\r%s %s %d/%d (%.1f%%) | Found: %s   ",
		p.colorize(colorBlue, "[SCAN]"),
		p.colorize(colorCyan, bar),
		done, total, pct,
		p.colorize(colorGreen+colorBold, fmt.Sprintf("%d", found)),
	)
	if done == total {
		fmt.Println()
	}
}

func (p *Printer) Found(r scanner.Result) {
	sizeStr := formatSize(r.Size)
	magic := ""
	if r.MagicMatch {
		magic = p.colorize(colorGreen, " [MAGIC✓]")
	}

	fmt.Printf("%s %s %s [%s] [%s]%s\n",
		p.colorize(colorGreen+colorBold, "[FOUND]"),
		p.colorize(colorWhite+colorBold, r.URL),
		p.colorize(colorGreen, fmt.Sprintf("(%d)", r.Status)),
		p.colorize(colorYellow, sizeStr),
		p.colorize(colorDim, r.ResponseTime.Round(time.Millisecond).String()),
		magic,
	)
}

func buildProgressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return "[" + bar + "]"
}

func formatSize(size int64) string {
	if size < 0 {
		return "?"
	}
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(size)/1024)
	}
	if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(size)/1024/1024)
	}
	return fmt.Sprintf("%.1fGB", float64(size)/1024/1024/1024)
}

// SaveResult is for JSON serialization
type SaveResult struct {
	URL          string `json:"url"`
	Status       int    `json:"status"`
	Size         int64  `json:"size"`
	ContentType  string `json:"content_type"`
	ResponseTime string `json:"response_time"`
	MagicMatch   bool   `json:"magic_bytes_match"`
	Timestamp    string `json:"timestamp"`
}

// Save writes results to file
func Save(path string, results []scanner.Result) error {
	now := time.Now().Format(time.RFC3339)

	var saveResults []SaveResult
	for _, r := range results {
		saveResults = append(saveResults, SaveResult{
			URL:          r.URL,
			Status:       r.Status,
			Size:         r.Size,
			ContentType:  r.ContentType,
			ResponseTime: r.ResponseTime.Round(time.Millisecond).String(),
			MagicMatch:   r.MagicMatch,
			Timestamp:    now,
		})
	}

	lpath := strings.ToLower(path)

	if strings.HasSuffix(lpath, ".json") {
		return saveJSON(path, saveResults)
	}
	return saveTXT(path, saveResults)
}

func saveJSON(path string, results []SaveResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{
		"tool":      "z1pfd",
		"author":    "Baba01hacker666",
		"team":      "Doraemon Cyber Team",
		"timestamp": time.Now().Format(time.RFC3339),
		"count":     len(results),
		"results":   results,
	})
}

func saveTXT(path string, results []SaveResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# z1pfd results | Doraemon Cyber Team | %s\n\n", time.Now().Format(time.RFC3339))
	for _, r := range results {
		fmt.Fprintf(f, "[%d] %s | %s | %s\n",
			r.Status, r.URL, formatSizeFromInt(r.Size), r.ResponseTime)
	}
	return nil
}

func formatSizeFromInt(size int64) string {
	if size < 0 {
		return "?"
	}
	if size < 1024 {
		return fmt.Sprintf("%dB", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(size)/1024)
	}
	if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(size)/1024/1024)
	}
	return fmt.Sprintf("%.1fGB", float64(size)/1024/1024/1024)
}
