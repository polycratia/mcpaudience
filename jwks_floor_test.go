package mcpaudience

import (
	"context"
	"errors"
	"testing"
	"time"
)

// MinRefresh is one floor for every key id, so the fetch a token naming an
// invented kid spends is a fetch the rotation arriving behind it does not get:
// a genuine token signed with a key published a second ago is refused until the
// interval lapses, which is the price the interval charges for keeping a stream
// of invented key ids from becoming a stream of requests at the issuer.
func TestTheSharedRefreshFloorDelaysARealRotationByAtMostMinRefresh(t *testing.T) {
	old, rotated := newSigner(t), newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &old.rsaKey.PublicKey))

	clock := now
	// MinRefresh is left at its default of 30s: this is the stock floor.
	set := &JWKS{URL: issuer.url, CacheFor: time.Hour, Now: func() time.Time { return clock }}
	v := &JWTVerifier{
		Resource: resource,
		Issuers:  []string{"https://auth.example.com"},
		KeySet:   set,
		Now:      func() time.Time { return clock },
	}

	// t=0: a token names a key id nobody published. It costs one fetch, and the
	// set that comes back is a verdict on the token rather than an outage.
	_, err := v.Verify(context.Background(), old.sign(t, "RS256", "rsa-9", goodClaims()))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature for a key id the issuer does not publish", err)
	}
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times, want the invented key id to have fetched once", got)
	}

	// t=1: the issuer publishes rsa-2 and starts signing with it.
	clock = now.Add(time.Second)
	issuer.publish(rsaJWK("rsa-1", &old.rsaKey.PublicKey), rsaJWK("rsa-2", &rotated.rsaKey.PublicKey))
	genuine := rotated.sign(t, "RS256", "rsa-2", goodClaims())

	// t=2: the rotation is real, but the floor was spent by the invented key id.
	clock = now.Add(2 * time.Second)
	if _, err := v.Verify(context.Background(), genuine); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want the genuine token refused while the floor is held", err)
	}
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times inside the interval, want once", got)
	}

	// t=31: the interval has lapsed, so the same token verifies on the second
	// fetch. The delay is bounded by MinRefresh and no longer.
	clock = now.Add(31 * time.Second)
	claims, err := v.Verify(context.Background(), genuine)
	if err != nil {
		t.Fatalf("the rotated key was still refused past MinRefresh: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("claims = %+v, want the verified token", claims)
	}
	if got := issuer.count(); got != 2 {
		t.Errorf("the issuer was asked %d times, want exactly twice", got)
	}
}
