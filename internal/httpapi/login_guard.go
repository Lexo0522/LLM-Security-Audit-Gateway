package httpapi

import (
	"strings"
	"sync"
	"time"
)

// loginGuard throttles administrator sign-ins per account. After
// maxFailures wrong passwords inside one window the account refuses logins
// until the lockout elapses, blunting online password guessing even when
// attempts come from many addresses. State is per-process: a restart clears
// it, which only shortens a lockout and never weakens the per-IP throttle.
type loginGuard struct {
	mu          sync.Mutex
	maxFailures int
	window      time.Duration
	entries     map[string]*loginFailures
	now         func() time.Time
}

type loginFailures struct {
	windowStart time.Time
	lockedUntil time.Time
	count       int
}

func newLoginGuard(maxFailures int, window time.Duration) *loginGuard {
	if maxFailures < 1 {
		maxFailures = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &loginGuard{maxFailures: maxFailures, window: window, entries: map[string]*loginFailures{}, now: time.Now}
}

// blocked reports whether the account is currently locked out.
func (g *loginGuard) blocked(username string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.entries[strings.ToLower(username)]
	if !ok {
		return false
	}
	return g.now().Before(entry.lockedUntil)
}

// fail records a wrong password and locks the account once the failure
// budget for the current window is exhausted.
func (g *loginGuard) fail(username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	key := strings.ToLower(username)
	entry, ok := g.entries[key]
	if !ok || now.Sub(entry.windowStart) > g.window {
		entry = &loginFailures{windowStart: now}
		g.entries[key] = entry
	}
	entry.count++
	if entry.count >= g.maxFailures {
		entry.lockedUntil = now.Add(g.window)
		entry.count = 0
		entry.windowStart = now
	}
}

// success clears the failure history for the account.
func (g *loginGuard) success(username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.entries, strings.ToLower(username))
}
