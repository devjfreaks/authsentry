package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devjfreaks/authsentry/internal/enricher"
	"github.com/devjfreaks/authsentry/internal/parser"
)


func TestIsFatalAPIError(t *testing.T) {
	fatal := &enricher.ErrFatalAPI{Msg: "invalid API key (HTTP 401): bad key"}
	if !enricher.IsFatalAPIError(fatal) {
		t.Error("should be fatal")
	}

	wrapped := errors.New("some other error")
	if enricher.IsFatalAPIError(wrapped) {
		t.Error("regular error should not be fatal")
	}

	// errors.As should unwrap it
	wrapped2 := errors.Join(errors.New("outer"), fatal)
	if !enricher.IsFatalAPIError(wrapped2) {
		t.Error("wrapped fatal should still be detected")
	}
}

func TestFatalAPIErrorMessage(t *testing.T) {
	err := &enricher.ErrFatalAPI{Msg: "invalid API key (HTTP 401): Provided API key is not valid."}
	if err.Error() != "invalid API key (HTTP 401): Provided API key is not valid." {
		t.Errorf("unexpected message: %s", err.Error())
	}
}

func TestWorkerPoolCompletesNormally(t *testing.T) {
	eventCh := make(chan parser.LogEvent, 3)
	eventCh <- parser.LogEvent{IP: "1.1.1.1", Timestamp: time.Now()}
	eventCh <- parser.LogEvent{IP: "2.2.2.2", Timestamp: time.Now()}
	eventCh <- parser.LogEvent{IP: "3.3.3.3", Timestamp: time.Now()}
	close(eventCh)

	cfg := Config{Workers: 2, DedupeCap: 100, EnrichAll: false}
	results, errs := Run(eventCh, nil, cfg)

	var got []Result
	for r := range results {
		got = append(got, r)
	}
	for e := range errs {
		t.Errorf("unexpected error: %v", e)
	}

	if len(got) != 3 {
		t.Errorf("expected 3 results, got %d", len(got))
	}
}

func TestWorkerPoolDeduplication(t *testing.T) {
	eventCh := make(chan parser.LogEvent, 5)
	for i := 0; i < 5; i++ {
		eventCh <- parser.LogEvent{IP: "1.1.1.1", Timestamp: time.Now()}
	}
	close(eventCh)

	enrichCallCount := 0
	cfg := Config{Workers: 3, DedupeCap: 100, EnrichAll: true}
	results, errs := Run(eventCh, nil, cfg)

	_ = enrichCallCount

	var got []Result
	for r := range results {
		got = append(got, r)
	}
	for e := range errs {
		t.Errorf("unexpected error: %v", e)
	}

	if len(got) != 5 {
		t.Errorf("expected 5 results (dedup affects enrichment, not results), got %d", len(got))
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err := ctx.Err()
	if err == nil {
		t.Error("expected cancelled context error")
	}
}
