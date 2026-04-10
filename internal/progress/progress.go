
package progress

import (
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

type Tracker struct {
	TotalEvents   atomic.Int64 // log lines parsed
	Enriched      atomic.Int64 // unique IPs sent to the live API
	CacheHits     atomic.Int64 // IPs served from the SQLite cache
	Errors        atomic.Int64 // enrichment errors
	TotalToEnrich int64        // set once before starting, used for % bar

	out     io.Writer
	done    chan struct{}
	stopped atomic.Bool
}

func New(w io.Writer, totalToEnrich int) *Tracker {
	return &Tracker{
		out:           w,
		done:          make(chan struct{}),
		TotalToEnrich: int64(totalToEnrich),
	}
}

func (t *Tracker) Start() {
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.print()
			case <-t.done:
				t.print()        // one final update with final numbers
				fmt.Fprintln(t.out) // newline so the next log line starts clean
				return
			}
		}
	}()
}

func (t *Tracker) Stop() {
	if t.stopped.CompareAndSwap(false, true) {
		close(t.done)
	}
}

func (t *Tracker) RecordEvent() { t.TotalEvents.Add(1) }

func (t *Tracker) RecordEnriched() { t.Enriched.Add(1) }

func (t *Tracker) RecordCacheHit() { t.CacheHits.Add(1) }

func (t *Tracker) RecordError() { t.Errors.Add(1) }

func (t *Tracker) print() {
	events := t.TotalEvents.Load()
	enriched := t.Enriched.Load()
	cacheHits := t.CacheHits.Load()
	errs := t.Errors.Load()

	bar := ""
	if t.TotalToEnrich > 0 {
		done := enriched + cacheHits
		pct := float64(done) / float64(t.TotalToEnrich) * 100
		if pct > 100 {
			pct = 100
		}
		filled := int(pct / 5) // 20 blocks = 100%; each block = 5%
		bar = fmt.Sprintf("  [%s%s] %.0f%%",
			strings.Repeat("█", filled),
			strings.Repeat("░", 20-filled),
			pct,
		)
	}

	errStr := ""
	if errs > 0 {
		errStr = fmt.Sprintf("  ⚠ %d error(s)", errs)
	}


	fmt.Fprintf(t.out,
		"\r  events parsed: %-7d  enriched: %-5d  cache hits: %-5d%s%s   ",
		events, enriched, cacheHits, bar, errStr,
	)
}
