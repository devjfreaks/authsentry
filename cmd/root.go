package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/devjfreaks/authsentry/internal/cache"
	"github.com/devjfreaks/authsentry/internal/enricher"
	"github.com/devjfreaks/authsentry/internal/parser"
	"github.com/devjfreaks/authsentry/internal/progress"
	"github.com/devjfreaks/authsentry/internal/reporter"
	"github.com/devjfreaks/authsentry/internal/worker"
)

var (
	apiKey       string
	logFormat    string
	outputFormat string
	outputFile   string
	workers      int
	rps          float64
	cacheFile    string
	cacheTTL     int
	maxEnrich    int
	enrichAll    bool
	noPrompt     bool
	dedupeCap    int
	includeFields []string
)

var rootCmd = &cobra.Command{
	Use:   "authsentry [log-file]",
	Short: "Suspicious login detector for auth logs",
	Long: `AuthSentry analyzes authentication log files and produces risk-scored reports.
It enriches IP addresses with geolocation and security intelligence to flag
credential stuffing, VPN abuse, and hosting-based attacks.

Supported log formats: django, laravel, rails, apache, nginx, raw
Output formats: html, json`,
	Args: cobra.ExactArgs(1),
	RunE: runAnalysis,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&apiKey, "api-key", "", "IPGeolocation API key (or set IPGEOLOCATION_API_KEY env)")
	rootCmd.Flags().StringVar(&logFormat, "format", "auto", "Log format: auto, django, laravel, rails, apache, nginx, raw")
	rootCmd.Flags().StringVar(&outputFormat, "output", "html", "Output format: html, json")
	rootCmd.Flags().StringVarP(&outputFile, "out", "o", "", "Output file path (default: stdout for json, report.html for html)")
	rootCmd.Flags().IntVar(&workers, "workers", 10, "Number of parallel enrichment workers")
	rootCmd.Flags().Float64Var(&rps, "rps", 10, "Max API requests per second")
	rootCmd.Flags().StringVar(&cacheFile, "cache", "cache.db", "SQLite cache file path")
	rootCmd.Flags().IntVar(&cacheTTL, "cache-ttl-hours", 24, "Cache TTL in hours")
	rootCmd.Flags().IntVar(&maxEnrich, "max-enrich", 0, "Max IPs to enrich (0 = prompt)")
	rootCmd.Flags().BoolVar(&enrichAll, "enrich-all", false, "Enrich all IPs without prompting")
	rootCmd.Flags().BoolVar(&noPrompt, "no-prompt", false, "Disable interactive prompts (non-interactive mode)")
	rootCmd.Flags().IntVar(&dedupeCap, "dedupe-cap", 100000, "In-memory dedup set capacity")
	rootCmd.Flags().StringSliceVar(&includeFields, "include", []string{}, "Include specific modules: location,security,asn,company")
}

func runAnalysis(cmd *cobra.Command, args []string) error {
	logPath := args[0]

	key := apiKey
	if key == "" {
		key = os.Getenv("IPGEOLOCATION_API_KEY")
	}

	f, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("cannot open log file: %w", err)
	}
	defer f.Close()

	format := logFormat
	if format == "auto" {
		format = detectFormat(logPath, f)
		f.Seek(0, 0)
		fmt.Fprintf(os.Stderr, "[authsentry] Detected log format: %s\n", format)
	}

	c, err := cache.New(cacheFile, cacheTTL)
	if err != nil {
		return fmt.Errorf("cache init failed: %w", err)
	}
	defer c.Close()

	p := parser.New(format)
	events, parseErrs := p.Stream(f)

	uniqueIPs := collectUniqueIPs(logPath, format)

	limit := resolveEnrichLimit(len(uniqueIPs), key)
	if limit == 0 && !enrichAll {
		fmt.Fprintln(os.Stderr, "[authsentry] No enrichment will be done. Producing report with parsed data only.")
	}

	e := enricher.New(key, c, rps, workers)


	prog := progress.New(os.Stderr, limit)

	cfg := worker.Config{
		Workers:   workers,
		DedupeCap: dedupeCap,
		MaxEnrich: limit,
		EnrichAll: enrichAll,
		Progress:  prog,
	}

	fmt.Fprintf(os.Stderr, "[authsentry] Processing log file...\n")
	prog.Start()

	results, procErrs := worker.Run(events, e, cfg)

	outPath := outputFile
	if outPath == "" && outputFormat == "html" {
		outPath = "report.html"
	}

	var out *os.File
	if outPath == "" {
		out = os.Stdout
	} else {
		out, err = os.Create(outPath)
		if err != nil {
			prog.Stop()
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer out.Close()
	}

	rep := reporter.New(outputFormat, out)
	if err := rep.Render(results); err != nil {
		prog.Stop()
		return fmt.Errorf("render failed: %w", err)
	}

	var fatalErr error
	go func() {
		for pe := range parseErrs {
			fmt.Fprintf(os.Stderr, "\n[parse error] %v\n", pe)
		}
	}()
	for procErr := range procErrs {
		msg := procErr.Error()
		if strings.HasPrefix(msg, "FATAL:") {
			fatalErr = procErr
		} else {
			fmt.Fprintf(os.Stderr, "\n[process error] %v\n", procErr)
		}
	}

	prog.Stop()

	if fatalErr != nil {
		fmt.Fprintf(os.Stderr, "[authsentry] %v\n", fatalErr)
		fmt.Fprintf(os.Stderr, "[authsentry] Aborted — report contains only events processed before the error.\n")
		if outPath != "" && rep.Count() > 0 {
			fmt.Fprintf(os.Stderr, "[authsentry] Partial report written to: %s (%d events)\n", outPath, rep.Count())
		}
		return fatalErr
	}

	if outPath != "" {
		fmt.Fprintf(os.Stderr, "[authsentry] Done. Report written to: %s (%d events)\n", outPath, rep.Count())
	}
	return nil
}

func detectFormat(path string, f *os.File) string {
	lower := strings.ToLower(path)
	if strings.Contains(lower, "django") {
		return "django"
	}
	if strings.Contains(lower, "laravel") {
		return "laravel"
	}
	if strings.Contains(lower, "rails") {
		return "rails"
	}

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "POST /login") || strings.Contains(line, "POST /session") {
			return "apache"
		}
		if strings.Contains(line, "Completed 2") || strings.Contains(line, "Started POST") {
			return "rails"
		}
		if strings.Contains(line, "authentication.login") || strings.Contains(line, "django.security") {
			return "django"
		}
		if strings.Contains(line, "production.ERROR") || strings.Contains(line, "production.INFO") {
			return "laravel"
		}
	}
	return "raw"
}

func collectUniqueIPs(path, format string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	p := parser.New(format)
	events, _ := p.Stream(f)

	seen := make(map[string]struct{})
	var ips []string
	for ev := range events {
		if _, ok := seen[ev.IP]; !ok {
			seen[ev.IP] = struct{}{}
			ips = append(ips, ev.IP)
		}
	}
	return ips
}

func resolveEnrichLimit(total int, apiKey string) int {
	if enrichAll {
		return total
	}
	if maxEnrich > 0 {
		return maxEnrich
	}
	if noPrompt {
		return total
	}
	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "[authsentry] No API key provided. Skipping enrichment.\n")
		fmt.Fprintf(os.Stderr, "[authsentry] Set IPGEOLOCATION_API_KEY or pass --api-key to enable enrichment.\n")
		return 0
	}

	fmt.Fprintf(os.Stderr, "[authsentry] Found %d unique IPs. Enrich all? [y/N/number]: ", total)
	var resp string
	fmt.Scanln(&resp)
	resp = strings.TrimSpace(strings.ToLower(resp))

	switch resp {
	case "y", "yes":
		return total
	case "n", "no", "":
		return 0
	default:
		var n int
		fmt.Sscanf(resp, "%d", &n)
		if n > 0 {
			return n
		}
		return 0
	}
}
