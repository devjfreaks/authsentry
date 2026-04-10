package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/template"
	"time"

	"github.com/devjfreaks/authsentry/internal/enricher"
	"github.com/devjfreaks/authsentry/internal/worker"
)

type Reporter struct {
	format  string
	out     io.Writer
	results []worker.Result
}

func New(format string, out io.Writer) *Reporter {
	return &Reporter{format: format, out: out}
}

func (r *Reporter) Count() int { return len(r.results) }

func (r *Reporter) Render(results <-chan worker.Result) error {
	for res := range results {
		r.results = append(r.results, res)
	}

	sort.Slice(r.results, func(i, j int) bool {
		if r.results[i].Risk.Score != r.results[j].Risk.Score {
			return r.results[i].Risk.Score > r.results[j].Risk.Score
		}
		return r.results[i].Timestamp.After(r.results[j].Timestamp)
	})

	switch r.format {
	case "json":
		return r.renderJSON()
	case "html":
		return r.renderHTML()
	default:
		return fmt.Errorf("unknown format: %s", r.format)
	}
}


func (r *Reporter) renderJSON() error {
	enc := json.NewEncoder(r.out)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"total":        len(r.results),
		"summary":      buildSummary(r.results),
		"events":       r.results,
	})
}


func (r *Reporter) renderHTML() error {
	summary := buildSummary(r.results)

	data := struct {
		GeneratedAt string
		Total       int
		Summary     Summary
		Results     []worker.Result
	}{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Total:       len(r.results),
		Summary:     summary,
		Results:     r.results,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"riskColor": riskColor,
		"riskBg":    riskBg,
		"fmtTime":   func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"join":      joinStrings,
		"boolYesNo": func(b bool) string {
			if b {
				return "Yes"
			}
			return "No"
		},
		"successLabel": func(b bool) string {
			if b {
				return "Success"
			}
			return "Failed"
		},
		"successClass": func(b bool) string {
			if b {
				return "success"
			}
			return "failure"
		},
		"countByLevel": func(level string) int {
			return summary.ByLevel[enricher.RiskLevel(level)]
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}

	return tmpl.Execute(r.out, data)
}


type Summary struct {
	ByLevel      map[enricher.RiskLevel]int `json:"by_level"`
	TopIPs       []IPCount                  `json:"top_ips"`
	UniqueIPs    int                        `json:"unique_ips"`
	FailedLogins int                        `json:"failed_logins"`
}

type IPCount struct {
	IP    string             `json:"ip"`
	Count int                `json:"count"`
	Level enricher.RiskLevel `json:"level"`
}

func buildSummary(results []worker.Result) Summary {
	byLevel := map[enricher.RiskLevel]int{}
	ipCounts := map[string]int{}
	ipLevel := map[string]enricher.RiskLevel{}
	uniqueIPs := map[string]struct{}{}
	failed := 0

	for _, r := range results {
		byLevel[r.Risk.Level]++
		ipCounts[r.IP]++
		uniqueIPs[r.IP] = struct{}{}
		if !r.Success {
			failed++
		}
		if existing, ok := ipLevel[r.IP]; !ok || riskOrdinal(r.Risk.Level) > riskOrdinal(existing) {
			ipLevel[r.IP] = r.Risk.Level
		}
	}

	var topIPs []IPCount
	for ip, cnt := range ipCounts {
		topIPs = append(topIPs, IPCount{IP: ip, Count: cnt, Level: ipLevel[ip]})
	}
	sort.Slice(topIPs, func(i, j int) bool {
		if topIPs[i].Count != topIPs[j].Count {
			return topIPs[i].Count > topIPs[j].Count
		}
		return riskOrdinal(topIPs[i].Level) > riskOrdinal(topIPs[j].Level)
	})
	if len(topIPs) > 10 {
		topIPs = topIPs[:10]
	}

	return Summary{
		ByLevel:      byLevel,
		TopIPs:       topIPs,
		UniqueIPs:    len(uniqueIPs),
		FailedLogins: failed,
	}
}

func riskOrdinal(l enricher.RiskLevel) int {
	switch l {
	case enricher.RiskCritical:
		return 4
	case enricher.RiskHigh:
		return 3
	case enricher.RiskMedium:
		return 2
	case enricher.RiskLow:
		return 1
	default:
		return 0
	}
}

func riskColor(level enricher.RiskLevel) string {
	switch level {
	case enricher.RiskCritical:
		return "#ff2d55"
	case enricher.RiskHigh:
		return "#ff9500"
	case enricher.RiskMedium:
		return "#ffcc00"
	case enricher.RiskLow:
		return "#34c759"
	default:
		return "#8e8e93"
	}
}

func riskBg(level enricher.RiskLevel) string {
	switch level {
	case enricher.RiskCritical:
		return "rgba(255,45,85,0.12)"
	case enricher.RiskHigh:
		return "rgba(255,149,0,0.10)"
	case enricher.RiskMedium:
		return "rgba(255,204,0,0.10)"
	case enricher.RiskLow:
		return "rgba(52,199,89,0.08)"
	default:
		return "rgba(142,142,147,0.06)"
	}
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
