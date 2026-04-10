package ratelimit

import (
	"context"
	"sync"
	"time"
)

type Limiter struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	burst    float64
	tokens   float64
	lastTime time.Time
}

func NewLimiter(ratePerSec float64, burst int) *Limiter {
	return &Limiter{
		rate:     ratePerSec,
		burst:    float64(burst),
		tokens:   float64(burst),
		lastTime: time.Now(),
	}
}

func (l *Limiter) Wait(ctx context.Context) error {
	for {
		delay := l.reserve()
		if delay <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (l *Limiter) reserve() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastTime).Seconds()
	l.lastTime = now

	l.tokens += elapsed * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}

	if l.tokens >= 1 {
		l.tokens--
		return 0
	}

	wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
	return wait
}
