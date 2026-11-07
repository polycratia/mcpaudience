package mcpaudience

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// outage is a verifier failure that knows how long it will go on failing, the
// shape the key set cache reports when it is holding the next fetch off.
type outage struct{ wait time.Duration }

func (o outage) Error() string             { return ErrUnavailable.Error() }
func (o outage) Unwrap() error             { return ErrUnavailable }
func (o outage) RetryAfter() time.Duration { return o.wait }

func (o outage) Verify(context.Context, string) (Claims, error) { return Claims{}, o }

// Retry-After is whole seconds, and a wait shorter than one of them is still a
// wait: rendering it as "0" sends the client straight back into the failure it
// was just told to wait out.
func TestTheRetryAfterRoundsAnyPositiveWaitUpToASecond(t *testing.T) {
	cases := map[string]struct {
		wait time.Duration
		want string
	}{
		"unsaid":            {0, "30"},
		"a fraction of one": {200 * time.Millisecond, "1"},
		"exactly one":       {time.Second, "1"},
		"a nanosecond over": {time.Second + time.Nanosecond, "2"},
		"most of a minute":  {29*time.Second + 100*time.Millisecond, "30"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			response := call(guard(outage{wait: c.wait}), okHandler(), "Bearer abc")

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", response.Code)
			}
			if got := response.Header().Get("Retry-After"); got != c.want {
				t.Errorf("Retry-After = %q, want %q", got, c.want)
			}
			if challenge := response.Header().Get("WWW-Authenticate"); challenge != "" {
				t.Errorf("challenge = %q, want none: no verdict on the token was reached", challenge)
			}
		})
	}
}

// The wait the 503 names is the one the cache is actually holding: MinRefresh
// declined the next fetch, and what is left of the interval is what the client
// is told to wait.
func TestTheWaitLeftOnTheRefreshIntervalIsWhatTheClientIsTold(t *testing.T) {
	clock := now
	keys := &JWKS{
		// Nothing listens here, so the first fetch fails and starts the interval.
		URL:        "https://127.0.0.1:1/.well-known/jwks.json",
		Client:     &http.Client{Timeout: 2 * time.Second},
		MinRefresh: 30 * time.Second,
		Now:        func() time.Time { return clock },
	}
	if _, err := keys.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable with no key set held", err)
	}
	clock = clock.Add(29*time.Second + 500*time.Millisecond)

	s := newSigner(t)
	v := &JWTVerifier{
		Resource: resource,
		Issuers:  []string{"https://auth.example.com"},
		KeySet:   keys,
		Now:      func() time.Time { return clock },
	}
	response := call(guard(v), okHandler(), "Bearer "+s.sign(t, "RS256", "rsa-1", goodClaims()))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if got := response.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want the 500ms left on the interval rounded up to 1", got)
	}
}

// The failure that starts the interval knows it too. The attempt is recorded
// before the request goes out, so a fetch that fails holds the next one off for
// the whole of MinRefresh — and that, not the fallback, is the wait the 503
// names. The fallback is left for a failure that says nothing at all.
func TestTheIntervalAFailedFetchJustStartedIsWhatTheClientIsTold(t *testing.T) {
	keys := &JWKS{
		// Nothing listens here, so this first fetch fails.
		URL:        "https://127.0.0.1:1/.well-known/jwks.json",
		Client:     &http.Client{Timeout: 2 * time.Second},
		MinRefresh: 10 * time.Second,
		Now:        func() time.Time { return now },
	}
	s := newSigner(t)
	v := &JWTVerifier{
		Resource: resource,
		Issuers:  []string{"https://auth.example.com"},
		KeySet:   keys,
		Now:      func() time.Time { return now },
	}
	response := call(guard(v), okHandler(), "Bearer "+s.sign(t, "RS256", "rsa-1", goodClaims()))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if got := response.Header().Get("Retry-After"); got != "10" {
		t.Errorf("Retry-After = %q, want the 10s interval the failed attempt spent rather than the 30s fallback", got)
	}
}

// The interval has to survive the trip through the verifier, because the error
// the guard builds its 503 on is the one Verify handed back and not the one the
// cache handed Key. Reading it off JWKS.Key only proves the cache attached it;
// reading it off Verify proves nothing in between dropped it — a wrap in
// ErrBadSignature would, leaving the 503 to name the fixed fallback and send
// every client back at a time this cache never chose.
func TestTheWaitIsReadOffWhatTheVerifierReturnsRatherThanTheKeySet(t *testing.T) {
	clock := now
	keys := &JWKS{
		// Nothing listens here, so the first fetch fails and starts the interval.
		URL:        "https://127.0.0.1:1/.well-known/jwks.json",
		Client:     &http.Client{Timeout: 2 * time.Second},
		MinRefresh: 45 * time.Second,
		Now:        func() time.Time { return clock },
	}
	if _, err := keys.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable with no key set held", err)
	}
	clock = clock.Add(15 * time.Second)

	s := newSigner(t)
	v := &JWTVerifier{
		Resource: resource,
		Issuers:  []string{"https://auth.example.com"},
		KeySet:   keys,
		Now:      func() time.Time { return clock },
	}
	_, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", goodClaims()))

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want nothing about the signature: it was never checked", err)
	}

	var waiter retryWaiter
	if !errors.As(err, &waiter) {
		t.Fatalf("err = %v, want the wait to reach the verifier's caller", err)
	}
	if got := waiter.RetryAfter(); got != 30*time.Second {
		t.Errorf("RetryAfter = %s, want the 30s left of the 45s interval", got)
	}
}
