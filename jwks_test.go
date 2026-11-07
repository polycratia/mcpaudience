package mcpaudience

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// keyServer stands in for an authorization server publishing its key set, and
// counts what the verifier asks of it.
type keyServer struct {
	url string

	mu       sync.Mutex
	keys     []map[string]any
	status   int
	requests int
}

func (k *keyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.requests++
	if k.status != 0 && k.status != http.StatusOK {
		http.Error(w, "the issuer is down", k.status)
		return
	}
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": k.keys})
}

func (k *keyServer) publish(keys ...map[string]any) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys = keys
}

func (k *keyServer) fail(status int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.status = status
}

func (k *keyServer) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.requests
}

func newKeyServer(t *testing.T, keys ...map[string]any) *keyServer {
	t.Helper()
	k := &keyServer{keys: keys}
	server := httptest.NewServer(k)
	t.Cleanup(server.Close)
	k.url = server.URL
	return k
}

func rsaJWK(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func ecJWK(kid string, key *ecdsa.PublicKey) map[string]any {
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return map[string]any{
		"kty": "EC", "kid": kid, "crv": "P-256", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

func keySetVerifier(set *JWKS) *JWTVerifier {
	return &JWTVerifier{
		Resource: resource,
		Issuers:  []string{"https://auth.example.com"},
		KeySet:   set,
		Now:      func() time.Time { return now },
	}
}

func TestKeysAreFetchedByKeyIDAndThenReused(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey), ecJWK("ec-1", &s.ecKey.PublicKey))
	v := keySetVerifier(&JWKS{URL: issuer.url, Now: func() time.Time { return now }})

	for _, algorithm := range []struct{ alg, kid string }{{"RS256", "rsa-1"}, {"ES256", "ec-1"}} {
		claims, err := v.Verify(context.Background(), s.sign(t, algorithm.alg, algorithm.kid, goodClaims()))
		if err != nil {
			t.Fatalf("%s: %v", algorithm.alg, err)
		}
		if claims.Subject != "user-1" {
			t.Errorf("%s: claims = %+v", algorithm.alg, claims)
		}
	}
	if got := issuer.count(); got != 1 {
		t.Errorf("the key set was fetched %d times for two tokens, want once", got)
	}
}

// An issuer signs with a new key as soon as it publishes it. Waiting for a TTL
// to lapse refuses every token minted in between.
func TestARotatedKeyIsFetchedBeforeTheCacheExpires(t *testing.T) {
	old, rotated := newSigner(t), newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &old.rsaKey.PublicKey))

	clock := now
	v := keySetVerifier(&JWKS{URL: issuer.url, CacheFor: time.Hour, Now: func() time.Time { return clock }})
	if _, err := v.Verify(context.Background(), old.sign(t, "RS256", "rsa-1", goodClaims())); err != nil {
		t.Fatal(err)
	}

	issuer.publish(rsaJWK("rsa-2", &rotated.rsaKey.PublicKey))
	clock = now.Add(time.Minute)

	if _, err := v.Verify(context.Background(), rotated.sign(t, "RS256", "rsa-2", goodClaims())); err != nil {
		t.Errorf("a key published after the set was cached was refused: %v", err)
	}
}

// Refetching on an unknown kid is free traffic at the issuer unless it is rate
// limited: invented key ids must not become one request each.
func TestAnUnknownKeyIDIsNotAFetchPerToken(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	v := keySetVerifier(&JWKS{URL: issuer.url, MinRefresh: time.Minute, Now: func() time.Time { return now }})

	for i := 0; i < 5; i++ {
		_, err := v.Verify(context.Background(), s.sign(t, "RS256", "invented", goodClaims()))
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v, want ErrBadSignature", err)
		}
	}
	if got := issuer.count(); got != 1 {
		t.Errorf("the issuer was asked %d times for a key id it never published, want once", got)
	}
}

// The same promise when the tokens arrive together rather than one after
// another, which is the shape that actually turns up: a client with a stale or
// invented kid retries, and a server under load has those retries in flight at
// once. MinRefresh alone would not settle it — the interval is read and recorded
// under j.mu, and the lock is held across the fetch, so the callers queued
// behind the first one find the attempt already spent instead of each starting
// one of their own.
func TestParallelVerifiesOnAnUnknownKeyIDFetchTheKeySetOnce(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	v := keySetVerifier(&JWKS{URL: issuer.url, MinRefresh: time.Minute, Now: func() time.Time { return now }})
	// Signed before the goroutines start: the signer needs the test's t.
	token := s.sign(t, "RS256", "invented", goodClaims())

	const callers = 32
	start := make(chan struct{})
	failures := make(chan error, callers)
	var ready, done sync.WaitGroup
	ready.Add(callers)
	done.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			_, err := v.Verify(context.Background(), token)
			failures <- err
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(failures)

	for err := range failures {
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v, want ErrBadSignature from every caller", err)
		}
		if errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want a key id nobody published not to read as an outage", err)
		}
	}
	if got := issuer.count(); got != 1 {
		t.Errorf("the issuer was asked %d times by %d parallel verifies naming a key id it never published, want once", got, callers)
	}
}

// What the schedule is for, with the request path kept in the state that makes
// it necessary. A floor busy with invented key ids spends MinRefresh and brings
// the copy in memory no further forward: the first token fetches, every one
// after it is declined, and there is no fetch left on the request path to meet a
// rotation with. The issuer publishes rsa-2 ahead of using it, a tick fetches it
// — the interval does not hold a scheduled fetch off — and the first token ever
// to name rsa-2 passes on first try, from the copy that tick brought back,
// rather than after the interval lapses or a retry.
func TestAScheduledTickMeetsARotationTheBusyRequestPathCannot(t *testing.T) {
	old, rotated := newSigner(t), newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &old.rsaKey.PublicKey))

	clock := now
	set := &JWKS{
		URL:        issuer.url,
		CacheFor:   time.Hour,
		MinRefresh: time.Hour,
		Now:        func() time.Time { return clock },
	}
	v := keySetVerifier(set)

	// The floor. The first of these fetches the set; the rest are refused from
	// the copy it brought back.
	invented := func(from, to int) {
		t.Helper()
		for i := from; i < to; i++ {
			clock = now.Add(time.Duration(i) * time.Second)
			_, err := v.Verify(context.Background(), old.sign(t, "RS256", fmt.Sprintf("invented-%d", i), goodClaims()))
			if !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature for a key id nobody published", err)
			}
		}
	}
	invented(0, 6)
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times by a floor of invented key ids, want once", got)
	}

	// Rotation, published before anything is signed with it.
	issuer.publish(rsaJWK("rsa-1", &old.rsaKey.PublicKey), rsaJWK("rsa-2", &rotated.rsaKey.PublicKey))

	// The floor goes on, and goes on being declined, so nothing on the request
	// path notices the new key.
	invented(6, 12)
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times inside the interval, want the floor to have spent it once", got)
	}

	// The tick, driven here rather than waited for: this is the fetch Start makes
	// once a period, and the interval has nothing to say about it.
	clock = now.Add(time.Minute)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatalf("the scheduled fetch was declined by the interval the floor spent: %v", err)
	}
	if got := issuer.count(); got != 2 {
		t.Fatalf("the issuer was asked %d times, want the tick to have fetched the rotated set", got)
	}

	// The first token anyone has presented on the rotated key id, well inside the
	// interval the floor and the tick have both spent.
	clock = now.Add(time.Minute + time.Second)
	claims, err := v.Verify(context.Background(), rotated.sign(t, "RS256", "rsa-2", goodClaims()))
	if err != nil {
		t.Fatalf("the first token naming the rotated key id was refused with that key already held: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("claims = %+v", claims)
	}
	if got := issuer.count(); got != 2 {
		t.Errorf("the issuer was asked %d times, want the token answered from the copy the tick brought back", got)
	}
}

// The interval is spent by the attempt, not by its result: the attempt is
// recorded before the fetch is made, so a failed one and an abandoned one hold
// the next fetch off for just as long as a successful one. That is the case the
// interval exists for — an issuer that is down is where refetching on every
// arriving token does the most damage — and the cost is that recovery waits for
// the interval to lapse rather than for the next request.
func TestAFailedOrAbandonedFetchStillSpendsTheRefreshInterval(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	issuer.fail(http.StatusInternalServerError)

	clock := now
	set := &JWKS{URL: issuer.url, MinRefresh: time.Minute, Now: func() time.Time { return clock }}

	if _, err := set.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times for the first fetch, want once", got)
	}

	clock = now.Add(30 * time.Second)
	if _, err := set.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if got := issuer.count(); got != 1 {
		t.Errorf("the issuer was asked %d times inside the interval after a fetch that failed, want once", got)
	}

	// The issuer is answering again and the interval has lapsed, but this
	// request is abandoned before the fetch can finish. The attempt was still
	// recorded, so it spends the interval like any other.
	issuer.fail(http.StatusOK)
	clock = now.Add(time.Minute)
	abandoned, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := set.Key(abandoned, "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	spent := issuer.count()

	clock = now.Add(90 * time.Second)
	if _, err := set.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want the abandoned attempt to have spent the interval", err)
	}
	if got := issuer.count(); got != spent {
		t.Errorf("the issuer was asked again inside the interval an abandoned attempt spent: %d requests, want %d", got, spent)
	}

	// And when the interval lapses again, the fetch happens.
	clock = now.Add(2 * time.Minute)
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Errorf("the key was not fetched once the interval lapsed: %v", err)
	}
	if got := issuer.count(); got != spent+1 {
		t.Errorf("the issuer was asked %d times in total, want %d once the interval lapsed", got, spent+1)
	}
}

// Where the interval ends, exactly. MinRefresh is a floor on the gap between
// two attempts and the floor includes its own value: a gap of exactly the
// interval is no longer shorter than it, so the fetch goes out. That boundary is
// the one clients actually land on, because the wait a 503 names after a failed
// fetch is the whole of the interval — a caller that waits precisely as long as
// it was told arrives here, and reading the comparison the other way would
// decline it and tell it to wait the whole interval over again.
func TestARefreshAtExactlyMinRefreshAfterAFailedAttemptReachesTheIssuer(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	issuer.fail(http.StatusInternalServerError)

	clock := now
	set := &JWKS{URL: issuer.url, MinRefresh: time.Minute, Now: func() time.Time { return clock }}

	if _, err := set.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable with no key set held", err)
	}
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times for the fetch that failed, want once", got)
	}

	// A nanosecond short of the interval is still inside it, and the attempt the
	// failure recorded is what declines this one.
	clock = now.Add(time.Minute - time.Nanosecond)
	if _, err := set.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if got := issuer.count(); got != 1 {
		t.Fatalf("the issuer was asked %d times a nanosecond inside the interval, want once", got)
	}

	// Exactly the interval. The issuer is answering again, so the attempt that
	// goes out at the boundary is also the one that ends the outage.
	issuer.fail(http.StatusOK)
	clock = now.Add(time.Minute)
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatalf("a refresh exactly MinRefresh after the failed attempt was declined: %v", err)
	}
	if got := issuer.count(); got != 2 {
		t.Errorf("the issuer was asked %d times, want the attempt at the boundary to have reached it", got)
	}
}

// An issuer being unreachable is not evidence that the key it published stopped
// being its key, and the tokens it signed expire on their own.
func TestTheLastGoodKeySetSurvivesAnIssuerOutage(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	clock := now
	v := keySetVerifier(&JWKS{
		URL:        issuer.url,
		CacheFor:   time.Minute,
		MinRefresh: time.Second,
		Now:        func() time.Time { return clock },
	})
	if _, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", goodClaims())); err != nil {
		t.Fatal(err)
	}

	issuer.fail(http.StatusInternalServerError)
	clock = now.Add(10 * time.Minute)

	if _, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", goodClaims())); err != nil {
		t.Errorf("a cached key was dropped because the issuer was unreachable: %v", err)
	}
}

// MaxStale is the other reading of the same outage: a copy of the set that can
// no longer be confirmed stops answering once it is that far past the fetch
// that produced it, and what it answers then is the outage rather than a
// verdict on the token.
func TestMaxStaleBoundsHowLongTheLastGoodKeySetAnswers(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	clock := now
	set := &JWKS{
		URL:        issuer.url,
		CacheFor:   time.Minute,
		MinRefresh: time.Second,
		MaxStale:   10 * time.Minute,
		Now:        func() time.Time { return clock },
	}
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatal(err)
	}

	issuer.fail(http.StatusInternalServerError)

	clock = now.Add(5 * time.Minute)
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Errorf("a cached key was dropped while it was still inside MaxStale: %v", err)
	}

	clock = now.Add(12 * time.Minute)
	_, err := set.Key(context.Background(), "rsa-1")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable once the set was fetched longer than MaxStale ago", err)
	}
	if errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want a set nobody could refresh not to read as a bad signature", err)
	}

	// A 503 is what the guard turns that into: the signature was never checked
	// against anything current, so there is nothing to challenge.
	v := keySetVerifier(set)
	response := call(guard(v), okHandler(), "Bearer "+s.sign(t, "RS256", "rsa-1", goodClaims()))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", response.Code)
	}

	// The issuer answering again is what ends it, and the copy in memory is
	// usable the moment it can be confirmed.
	issuer.fail(http.StatusOK)
	clock = now.Add(20 * time.Minute)
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Errorf("the key was refused after the issuer came back: %v", err)
	}
}

// The bound is measured from the fetch that produced the copy in memory, not
// from the point it went stale. Counting it past CacheFor would make the oldest
// a key can be the sum of two settings, so a server asking for five minutes of
// unconfirmed keys would get six — and the longer CacheFor is, the further the
// bound it configured drifts from the one it gets.
func TestMaxStaleIsMeasuredFromTheLastSuccessfulFetch(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	clock := now
	set := &JWKS{
		URL:        issuer.url,
		CacheFor:   time.Minute,
		MinRefresh: time.Second,
		MaxStale:   5 * time.Minute,
		Now:        func() time.Time { return clock },
	}
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatal(err)
	}

	issuer.fail(http.StatusInternalServerError)

	clock = now.Add(4 * time.Minute)
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Errorf("a key fetched four minutes ago was dropped inside the five-minute bound: %v", err)
	}

	// Past MaxStale from the fetch, and still inside CacheFor plus MaxStale.
	clock = now.Add(330 * time.Second)
	_, err := set.Key(context.Background(), "rsa-1")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable: the copy in memory is older than MaxStale", err)
	}
	if !strings.Contains(err.Error(), set.MaxStale.String()) {
		t.Errorf("the refusal does not name the bound the set outlived: %v", err)
	}
}

// Token expiry is not the same bound, and an outage that outlasts MaxStale is
// where the two come apart. The tokens the cached key had already signed do
// expire on their own, but the issuer goes on minting fresh ones on that same
// kid for as long as the outage lasts, and those arrive with an hour left on
// them. So the question the cache answers is not whether this token is still
// live — it plainly is — but whether the key it names is still the issuer's,
// and past the bound nobody here can say. The refusal is the outage: a 503 and
// an interval, not a verdict on a credential minted a moment ago.
func TestAFreshTokenOnACachedKeyIDIsRefusedWhenTheOutageOutlastsMaxStale(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	clock := now
	set := &JWKS{
		URL:        issuer.url,
		CacheFor:   time.Minute,
		MinRefresh: time.Second,
		MaxStale:   10 * time.Minute,
		Now:        func() time.Time { return clock },
	}
	v := &JWTVerifier{
		Resource: resource,
		Issuers:  []string{"https://auth.example.com"},
		KeySet:   set,
		Now:      func() time.Time { return clock },
	}

	// A token the issuer signs on the cached kid at whatever the clock says now,
	// so nothing about it has aged by the time it is presented.
	minted := func() string {
		claims := goodClaims()
		claims["iat"] = clock.Unix()
		claims["exp"] = clock.Add(time.Hour).Unix()
		return s.sign(t, "RS256", "rsa-1", claims)
	}

	if _, err := v.Verify(context.Background(), minted()); err != nil {
		t.Fatal(err)
	}

	issuer.fail(http.StatusInternalServerError)

	clock = now.Add(9 * time.Minute)
	if _, err := v.Verify(context.Background(), minted()); err != nil {
		t.Errorf("a token minted during the outage was refused inside MaxStale: %v", err)
	}

	clock = now.Add(11 * time.Minute)
	fresh := minted()
	_, err := v.Verify(context.Background(), fresh)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable: the copy in memory outlived the bound", err)
	}
	if errors.Is(err, ErrExpired) || errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want the outage rather than a verdict on a token minted a moment ago", err)
	}

	response := call(guard(v), okHandler(), "Bearer "+fresh)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if response.Header().Get("Retry-After") == "" {
		t.Error("a 503 with no Retry-After leaves the client to invent an interval")
	}
	if challenge := response.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Errorf("challenge = %q, want none: the signature was never checked against anything current", challenge)
	}

	// Unset, there is no bound, and that is the trade the other way: the same
	// fresh token keeps being verified against a copy nobody can confirm.
	set.MaxStale = 0
	if _, err := v.Verify(context.Background(), fresh); err != nil {
		t.Errorf("without MaxStale the last good set should go on answering: %v", err)
	}
}

// A cold cache has no last good set to fall back on, and that is not a verdict
// on the token: the signature was never checked. A 401 invalid_token would send
// the client to its issuer for a replacement that fails the same way, so the
// honest answer is 503 and an interval to wait.
func TestAnUnreachableIssuerOnAColdCacheIsNotTheTokensFault(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	issuer.fail(http.StatusBadGateway)

	v := keySetVerifier(&JWKS{URL: issuer.url, Now: func() time.Time { return now }})
	token := s.sign(t, "RS256", "rsa-1", goodClaims())

	_, err := v.Verify(context.Background(), token)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want a failed fetch not to read as a bad signature", err)
	}

	response := call(guard(v), okHandler(), "Bearer "+token)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if response.Header().Get("Retry-After") == "" {
		t.Error("a 503 with no Retry-After leaves the client to invent an interval")
	}
	if challenge := response.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Errorf("challenge = %q, want none: nothing is known to be wrong with the credential", challenge)
	}
}

// The other side of that line. The issuer answered, the set it published does
// not name this key id, and that is a refusal rather than an outage: retrying
// buys the client nothing, a different token might.
func TestAKeyIDMissingFromAFreshKeySetIsStillAnInvalidToken(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	v := keySetVerifier(&JWKS{URL: issuer.url, Now: func() time.Time { return now }})
	token := s.sign(t, "RS256", "rsa-9", goodClaims())

	_, err := v.Verify(context.Background(), token)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want a key id nobody published not to read as an outage", err)
	}

	response := call(guard(v), okHandler(), "Bearer "+token)
	if response.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", response.Code)
	}
}

// A symmetric key in a set of public keys is the algorithm-confusion attack
// with the secret handed over in advance. Nothing usable is left in the set, so
// there is no verdict to give either — only the reason it could not be reached.
func TestASymmetricKeyInThePublishedSetIsRefused(t *testing.T) {
	secret := []byte("a shared secret that has no business being published")
	issuer := newKeyServer(t, map[string]any{
		"kty": "oct", "kid": "shared",
		"k": base64.RawURLEncoding.EncodeToString(secret),
	})
	v := keySetVerifier(&JWKS{URL: issuer.url, Now: func() time.Time { return now }})

	signed := segment(map[string]string{"alg": "HS256", "kid": "shared"}) + "." + segment(goodClaims())
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signed))
	forged := signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	_, err := v.Verify(context.Background(), forged)
	if err == nil {
		t.Fatal("a token signed with a published symmetric key was accepted")
	}
	if !strings.Contains(err.Error(), "symmetric") {
		t.Errorf("the refusal does not say what was wrong with the key: %v", err)
	}
}

func TestAFetchedKeyDoesNotMakeAlgNoneAcceptable(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	v := keySetVerifier(&JWKS{URL: issuer.url, Now: func() time.Time { return now }})

	_, err := v.Verify(context.Background(), s.sign(t, "none", "rsa-1", goodClaims()))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	if !strings.Contains(err.Error(), "trust me") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}
}

// The refusal comes before the first request rather than after it.
func TestAKeySetOverPlainHTTPIsRefused(t *testing.T) {
	set := &JWKS{URL: "http://auth.example.com/.well-known/jwks.json"}

	_, err := set.Key(context.Background(), "rsa-1")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("err = %v, want a refusal that names the scheme", err)
	}
}

func TestAKeySetWithNothingUsableInItIsAnError(t *testing.T) {
	issuer := newKeyServer(t, map[string]any{"kty": "RSA", "kid": "rsa-1", "n": "!!!", "e": "AQAB"})
	set := &JWKS{URL: issuer.url, Now: func() time.Time { return now }}

	if _, err := set.Key(context.Background(), "rsa-1"); err == nil {
		t.Error("a key set with nothing usable in it was accepted as empty")
	}
}

// OnRefresh is a place to watch rotation from, not a worker, and where it runs
// is what decides that: on the goroutine of the request whose token triggered
// the fetch, after Key has let go of the lock the fetch was made under — so a
// callback that reads the cache it was just told about does not deadlock — and
// with no context of its own.
func TestTheRefreshCallbackRunsOnTheTriggeringRequestAfterTheLockIsReleased(t *testing.T) {
	s := newSigner(t)
	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))

	var (
		observed  []KeySetRefresh
		stack     string
		reentered bool
		reentry   error
	)
	set := &JWKS{URL: issuer.url, Now: func() time.Time { return now }}
	set.OnRefresh = func(r KeySetRefresh) {
		observed = append(observed, r)
		buffer := make([]byte, 8192)
		stack = string(buffer[:runtime.Stack(buffer, false)])
		if !reentered {
			reentered = true
			_, reentry = set.Key(context.Background(), "rsa-1")
		}
	}

	// A callback running under j.mu would leave that reentrant Key waiting for a
	// lock its own caller still holds, so the wait here is the assertion.
	done := make(chan error, 1)
	go func() {
		_, err := set.Key(context.Background(), "rsa-1")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Key never returned: the callback is running while j.mu is still held")
	}
	if reentry != nil {
		t.Errorf("the callback could not read the cache it was told about: %v", reentry)
	}

	if len(observed) != 1 {
		t.Fatalf("observed %d fetches, want the one that happened", len(observed))
	}
	fetch := observed[0]
	if fetch.KeyID != "rsa-1" || fetch.Err != nil || len(fetch.KeyIDs) != 1 || fetch.KeyIDs[0] != "rsa-1" {
		t.Errorf("fetch = %+v, want the triggering kid and the set it came back with", fetch)
	}
	if !fetch.At.Equal(now) {
		t.Errorf("At = %v, want the cache's clock", fetch.At)
	}
	if !strings.Contains(stack, "(*JWKS).Key") ||
		!strings.Contains(stack, "TestTheRefreshCallbackRunsOnTheTriggeringRequest") {
		t.Errorf("the callback is not on the caller's goroutine inside Key:\n%s", stack)
	}

	// A key answered from memory is not a fetch, so there is nothing to report.
	if _, err := set.Key(context.Background(), "rsa-1"); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 {
		t.Errorf("observed %d fetches, want a cache hit to report none", len(observed))
	}
}

// A fetch that failed is the one worth watching, so it is reported rather than
// swallowed: the error is there, and no key ids are claimed.
func TestTheRefreshCallbackReportsAFetchThatFailed(t *testing.T) {
	issuer := newKeyServer(t)
	issuer.fail(http.StatusBadGateway)

	var observed []KeySetRefresh
	set := &JWKS{
		URL:       issuer.url,
		Now:       func() time.Time { return now },
		OnRefresh: func(r KeySetRefresh) { observed = append(observed, r) },
	}

	if _, err := set.Key(context.Background(), "rsa-1"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if len(observed) != 1 {
		t.Fatalf("observed %d fetches, want the one that failed", len(observed))
	}
	if observed[0].Err == nil || len(observed[0].KeyIDs) != 0 {
		t.Errorf("fetch = %+v, want the error and no key ids", observed[0])
	}
}

// Clocks between an issuer and a resource server disagree, and the allowance is
// configured rather than assumed.
func TestConfiguredSkewMovesTheExpiryBoundary(t *testing.T) {
	s := newSigner(t)
	claims := goodClaims()
	claims["exp"] = now.Add(-2 * time.Minute).Unix()
	token := s.sign(t, "RS256", "rsa-1", claims)

	if _, err := verifier(s).Verify(context.Background(), token); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired with the default minute of skew", err)
	}

	tolerant := verifier(s)
	tolerant.Skew = 5 * time.Minute
	if _, err := tolerant.Verify(context.Background(), token); err != nil {
		t.Errorf("a token two minutes past expiry was refused despite five minutes of configured skew: %v", err)
	}
}
