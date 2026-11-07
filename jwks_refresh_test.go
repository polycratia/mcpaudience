package mcpaudience

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// MinRefresh bounds the fetches arriving tokens ask for, so that a stream of
// invented key ids cannot become a stream of requests at the issuer. A refresh
// the server makes on a schedule of its own is already bounded by that
// schedule, so the interval has nothing left to hold back and the fetch goes
// out whatever the interval would have said. The attempt is still recorded,
// because the request path is what reads it: a fetch that has just happened is
// a reason for the next arriving token not to start another.
func TestAScheduledRefreshIsNotHeldOffByTheIntervalButStillSpendsIt(t *testing.T) {
	old, rotated := newSigner(t), newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &old.rsaKey.PublicKey))

	var watched []KeySetRefresh
	clock := now
	set := &JWKS{
		URL:        issuer.url,
		CacheFor:   time.Hour,
		MinRefresh: time.Hour,
		Now:        func() time.Time { return clock },
		OnRefresh:  func(r KeySetRefresh) { watched = append(watched, r) },
	}
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatal(err)
	}

	issuer.publish(rsaJWK("rsa-2", &rotated.rsaKey.PublicKey))

	// A token naming the rotated key id arrives inside the interval, so the copy
	// in memory answers it and the issuer is left alone.
	clock = now.Add(time.Minute)
	if _, err := set.Key(context.Background(), "rsa-2"); err == nil {
		t.Fatal("a key id the set in memory does not name was answered")
	}
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times inside the interval, want once", got)
	}

	if err := set.Refresh(context.Background()); err != nil {
		t.Fatalf("a scheduled refresh was declined by the interval: %v", err)
	}
	if got := issuer.count(); got != 2 {
		t.Fatalf("the issuer was asked %d times, want the scheduled fetch to have gone out", got)
	}
	if _, err := set.Key(context.Background(), "rsa-2"); err != nil {
		t.Errorf("the rotated key was not held after the scheduled refresh: %v", err)
	}

	if len(watched) != 2 {
		t.Fatalf("observed %d fetches, want the first one and the scheduled one", len(watched))
	}
	scheduled := watched[1]
	if scheduled.KeyID != "" {
		t.Errorf("KeyID = %q, want none: no token asked for this fetch", scheduled.KeyID)
	}
	if len(scheduled.KeyIDs) != 1 || scheduled.KeyIDs[0] != "rsa-2" || scheduled.Err != nil {
		t.Errorf("fetch = %+v, want the set it came back with", scheduled)
	}

	// The attempt it recorded is what holds the request path off: a key id the
	// refreshed set does not name does not start a fetch of its own.
	clock = now.Add(2 * time.Minute)
	if _, err := set.Key(context.Background(), "rsa-9"); err == nil {
		t.Fatal("a key id nobody published was answered")
	}
	if got := issuer.count(); got != 2 {
		t.Errorf("the issuer was asked %d times after the scheduled fetch recorded its attempt, want twice", got)
	}
}

// A scheduled refresh that cannot reach the issuer is the outage, reported as
// one, and the copy in memory is left alone to go on answering.
func TestAScheduledRefreshThatCannotReachTheIssuerIsAnOutage(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	set := &JWKS{URL: issuer.url, CacheFor: time.Hour, Now: func() time.Time { return now }}
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatal(err)
	}

	issuer.fail(http.StatusInternalServerError)
	if err := set.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Errorf("the cached key was dropped by a refresh that failed: %v", err)
	}
}

// The scheme is refused before the first request on this path too.
func TestAScheduledRefreshOverPlainHTTPIsRefused(t *testing.T) {
	set := &JWKS{URL: "http://auth.example.com/.well-known/jwks.json"}

	err := set.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v, want a refusal that names the scheme", err)
	}
}

// Start is the schedule written out, so a server that wants the copy in memory
// kept warm does not write the goroutine itself. What it makes are scheduled
// fetches — the interval has nothing to hold back, so the rotation is met
// without a token having to ask for it — and stopping it stops them: a server
// that has shut down is not still asking its issuer for keys.
func TestStartFetchesOnATickerUntilItIsStopped(t *testing.T) {
	old, rotated := newSigner(t), newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &old.rsaKey.PublicKey))

	fetches := make(chan KeySetRefresh, 16)
	set := &JWKS{
		URL:        issuer.url,
		CacheFor:   time.Hour,
		MinRefresh: time.Hour,
		Now:        func() time.Time { return now },
		OnRefresh: func(r KeySetRefresh) {
			// Never blocking: a callback waiting on this test would hold the
			// ticker goroutine that stop() waits for.
			select {
			case fetches <- r:
			default:
			}
		},
	}
	issuer.publish(rsaJWK("rsa-2", &rotated.rsaKey.PublicKey))

	stop, err := set.Start(context.Background(), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	var fetch KeySetRefresh
	select {
	case fetch = <-fetches:
	case <-time.After(10 * time.Second):
		stop()
		t.Fatal("the ticker never fetched the key set")
	}
	if fetch.KeyID != "" {
		t.Errorf("KeyID = %q, want none: no token asked for a scheduled fetch", fetch.KeyID)
	}
	if len(fetch.KeyIDs) != 1 || fetch.KeyIDs[0] != "rsa-2" || fetch.Err != nil {
		t.Errorf("fetch = %+v, want the set the ticker brought back", fetch)
	}

	stop()

	if _, err := set.Key(context.Background(), "rsa-2"); err != nil {
		t.Errorf("the rotated key was not held after the ticker ran: %v", err)
	}

	stopped := issuer.count()
	time.Sleep(50 * time.Millisecond)
	if got := issuer.count(); got != stopped {
		t.Errorf("the issuer was asked %d times after stop, want the %d it had been asked by then", got, stopped)
	}

	stop() // stopping twice is a double defer, not a panic
}

// No period is CacheFor: the copy is refreshed about as often as it would
// otherwise go stale, which is the schedule a server reaching for this already
// configured.
func TestStartWithNoPeriodTicksOnCacheFor(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	fetched := make(chan struct{}, 1)
	set := &JWKS{
		URL:      issuer.url,
		CacheFor: 10 * time.Millisecond,
		Now:      func() time.Time { return now },
		OnRefresh: func(KeySetRefresh) {
			select {
			case fetched <- struct{}{}:
			default:
			}
		},
	}

	stop, err := set.Start(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	select {
	case <-fetched:
	case <-time.After(10 * time.Second):
		t.Fatal("no fetch was made on the CacheFor period")
	}
}

// A URL no fetch would accept is reported to whoever started the ticker, rather
// than to a goroutine that fails quietly once a period for the life of the
// process.
func TestStartRefusesAKeySetURLNoFetchWouldAccept(t *testing.T) {
	set := &JWKS{URL: "http://auth.example.com/.well-known/jwks.json"}

	stop, err := set.Start(context.Background(), time.Minute)
	if err == nil {
		stop()
		t.Fatal("a ticker was started against a key set URL that will never be fetched")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v, want a refusal that names the scheme", err)
	}
}
