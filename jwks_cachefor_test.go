package mcpaudience

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// CacheFor is the period a background refresh runs on, not a timer the request
// path consults: a key id the copy in memory holds is answered from it however
// long ago the set was fetched. Expiring the copy there bought nothing —
// rotation does not wait for the timer, which is why an unknown key id
// refetches — and cost a request at the issuer on whichever token happened to
// arrive after the lapse.
func TestCacheForDoesNotExpireTheCopyInMemoryOnTheRequestPath(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	clock := now
	set := &JWKS{URL: issuer.url, CacheFor: time.Minute, Now: func() time.Time { return clock }}
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatal(err)
	}

	clock = now.Add(time.Hour)
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatalf("a key the copy in memory holds was refused long past CacheFor: %v", err)
	}
	if got := issuer.count(); got != 1 {
		t.Errorf("the issuer was asked %d times for a key already held, want once", got)
	}

	// What does still reach the issuer: a key id the copy does not name.
	issuer.publish(rsaJWK("rsa-1", &s.rsaKey.PublicKey), rsaJWK("rsa-2", &s.rsaKey.PublicKey))
	if _, err := set.Key(context.Background(), "rsa-2"); err != nil {
		t.Fatalf("a rotated key id did not reach the issuer: %v", err)
	}
	if got := issuer.count(); got != 2 {
		t.Errorf("the issuer was asked %d times, want the unknown key id to have fetched", got)
	}
}

// MaxStale is the one age the request path does read, and it reads it whether
// or not a key id is missing: a copy past the bound has to be confirmed before
// the key it holds verifies anything, and an issuer that cannot confirm it is
// the outage rather than a verdict on the token.
func TestACopyPastMaxStaleIsConfirmedBeforeAKeyItHoldsAnswers(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	clock := now
	set := &JWKS{
		URL:        issuer.url,
		CacheFor:   time.Hour,
		MinRefresh: time.Second,
		MaxStale:   2 * time.Minute,
		Now:        func() time.Time { return clock },
	}
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatal(err)
	}

	clock = now.Add(3 * time.Minute)
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatalf("the key was refused by a fetch that confirmed the copy: %v", err)
	}
	if got := issuer.count(); got != 2 {
		t.Errorf("the issuer was asked %d times, want the copy past MaxStale to have been confirmed", got)
	}

	issuer.fail(http.StatusInternalServerError)
	clock = now.Add(6 * time.Minute)
	if _, err := set.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable once the copy could not be confirmed", err)
	}
}
