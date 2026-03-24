package api

import (
	"net/http"
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	capacity float64
}

func newRateLimiter(requestsPerMinute int) *rateLimiter {
	rl := &rateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     float64(requestsPerMinute) / 60.0,
		capacity: float64(requestsPerMinute),
	}
	// Periodically clean up old buckets
	go func() {
		for range time.Tick(10 * time.Minute) {
			rl.mu.Lock()
			for k, b := range rl.buckets {
				if time.Since(b.lastSeen) > 30*time.Minute {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.capacity}
		rl.buckets[key] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *rateLimiter) middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Strip port
		if i := len(ip) - 1; i >= 0 {
			for ; i >= 0; i-- {
				if ip[i] == ':' {
					ip = ip[:i]
					break
				}
			}
		}
		if !rl.allow(ip) {
			http.Error(w, `{"error":"RATE_LIMITED"}`, http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
