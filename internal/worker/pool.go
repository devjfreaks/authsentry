package worker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devjfreaks/authsentry/internal/enricher"
	"github.com/devjfreaks/authsentry/internal/parser"
	"github.com/devjfreaks/authsentry/internal/progress"
)

// Config holds worker pool configuration.
type Config struct {
	Workers   int
	DedupeCap int
	MaxEnrich int
	EnrichAll bool
	Progress  *progress.Tracker 
}

type Result struct {
	Timestamp time.Time          `json:"timestamp"`
	IP        string             `json:"ip"`
	Username  string             `json:"username"`
	Success   bool               `json:"success"`
	Endpoint  string             `json:"endpoint"`
	Format    string             `json:"format"`
	RawLine   string             `json:"raw_line"`
	IPData    *enricher.IPData   `json:"ip_data,omitempty"`
	Risk      enricher.RiskScore `json:"risk"`
}

func Run(events <-chan parser.LogEvent, e *enricher.Enricher, cfg Config) (<-chan Result, <-chan error) {
	results := make(chan Result, 512)
	errs := make(chan error, 64)

	go func() {
		defer close(results)
		defer close(errs)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var (
			wg          sync.WaitGroup
			mu          sync.Mutex
			dedupe      = make(map[string]struct{}, cfg.DedupeCap)
			enrichCount int64
			fatalOnce   sync.Once // ensure we only cancel + report once
		)

		prog := cfg.Progress // may be nil

		sem := make(chan struct{}, cfg.Workers)

		for ev := range events {
			if ctx.Err() != nil {
				break
			}

			if prog != nil {
				prog.RecordEvent()
			}

			ev := ev // capture loop variable

			mu.Lock()
			_, seen := dedupe[ev.IP]
			if !seen && len(dedupe) < cfg.DedupeCap {
				dedupe[ev.IP] = struct{}{}
			}
			mu.Unlock()

			wg.Add(1)
			sem <- struct{}{}

			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				var ipData *enricher.IPData

				shouldEnrich := !seen &&
					(cfg.EnrichAll || cfg.MaxEnrich == 0 || atomic.LoadInt64(&enrichCount) < int64(cfg.MaxEnrich))

				if shouldEnrich && e != nil {
					atomic.AddInt64(&enrichCount, 1)
					var enrichErr error
					ipData, enrichErr = e.Enrich(ctx, ev.IP)
					if enrichErr != nil {
						if enricher.IsFatalAPIError(enrichErr) {
							fatalOnce.Do(func() {
								if prog != nil {
									prog.RecordError()
								}
								errs <- fmt.Errorf("FATAL: %w — stopping all enrichment", enrichErr)
								cancel()
							})
						} else {
							if prog != nil {
								prog.RecordError()
							}
							errs <- fmt.Errorf("enrich %s: %w", ev.IP, enrichErr)
						}
					} else if ipData != nil {
						if ipData.FromCache {
							if prog != nil {
								prog.RecordCacheHit()
							}
						} else {
							if prog != nil {
								prog.RecordEnriched()
							}
						}
					}
				}

				risk := enricher.Score(ipData, ev.Success, ev.Username)

				results <- Result{
					Timestamp: ev.Timestamp,
					IP:        ev.IP,
					Username:  ev.Username,
					Success:   ev.Success,
					Endpoint:  ev.Endpoint,
					Format:    ev.Format,
					RawLine:   ev.RawLine,
					IPData:    ipData,
					Risk:      risk,
				}
			}()
		}

		wg.Wait()
	}()

	return results, errs
}
