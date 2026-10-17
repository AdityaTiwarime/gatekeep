// Package revoke is a small, thread-safe denylist of token IDs (jti).
//
// Entries only need to live until the token would have expired anyway,
// so the list stays small and cleans itself up.
package revoke

import (
	"sync"
	"time"
)

type Entry struct {
	JTI string `json:"jti"`
	Exp int64  `json:"exp"` // unix seconds
}

type List struct {
	mu  sync.RWMutex
	m   map[string]int64
	now func() time.Time
}

func New() *List { return &List{m: map[string]int64{}, now: time.Now} }

func (l *List) SetClock(now func() time.Time) { l.mu.Lock(); l.now = now; l.mu.Unlock() }

func (l *List) Add(jti string, exp time.Time) {
	if jti == "" {
		return
	}
	l.mu.Lock()
	l.m[jti] = exp.Unix()
	l.mu.Unlock()
}

func (l *List) Has(jti string) bool {
	l.mu.RLock()
	_, ok := l.m[jti]
	l.mu.RUnlock()
	return ok
}

// Replace swaps in a fresh copy (used by the proxy after each poll).
func (l *List) Replace(entries []Entry) {
	m := make(map[string]int64, len(entries))
	for _, e := range entries {
		m[e.JTI] = e.Exp
	}
	l.mu.Lock()
	l.m = m
	l.mu.Unlock()
}

// Snapshot drops expired entries and returns the rest.
func (l *List) Snapshot() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().Unix()
	out := make([]Entry, 0, len(l.m))
	for jti, exp := range l.m {
		if exp <= now {
			delete(l.m, jti)
			continue
		}
		out = append(out, Entry{JTI: jti, Exp: exp})
	}
	return out
}

func (l *List) Len() int { l.mu.RLock(); defer l.mu.RUnlock(); return len(l.m) }
