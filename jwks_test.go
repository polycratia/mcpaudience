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
	"math/big"
	"net/http"
	"net/http/httptest"
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

// A symmetric key in a set of public keys is the algorithm-confusion attack
// with the secret handed over in advance.
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
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
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
