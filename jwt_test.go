package mcpaudience

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const resource = "https://mcp.example.com"

var now = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

// signer builds real tokens with a real key, so the verifier is exercised
// against the thing it will actually see.
type signer struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{rsaKey: rsaKey, ecKey: ecKey}
}

func (s *signer) keys() map[string]crypto.PublicKey {
	return map[string]crypto.PublicKey{
		"rsa-1": &s.rsaKey.PublicKey,
		"ec-1":  &s.ecKey.PublicKey,
	}
}

func segment(v any) string {
	body, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(body)
}

func (s *signer) sign(t *testing.T, algorithm, kid string, claims map[string]any) string {
	t.Helper()
	signed := segment(map[string]string{"alg": algorithm, "kid": kid, "typ": "JWT"}) + "." + segment(claims)
	digest := sha256.Sum256([]byte(signed))

	var signature []byte
	var err error
	switch algorithm {
	case "RS256":
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.rsaKey, crypto.SHA256, digest[:])
	case "ES256":
		var r, sv []byte
		r, sv, err = signES256(s.ecKey, digest[:])
		signature = append(r, sv...)
	case "none":
		signature = nil
	default:
		t.Fatalf("test signer cannot produce %s", algorithm)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signES256(key *ecdsa.PrivateKey, digest []byte) ([]byte, []byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, nil, err
	}
	rb, sb := make([]byte, 32), make([]byte, 32)
	r.FillBytes(rb)
	s.FillBytes(sb)
	return rb, sb, nil
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss":   "https://auth.example.com",
		"sub":   "user-1",
		"aud":   resource,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "mcp:read mcp:write",
	}
}

func verifier(s *signer) *JWTVerifier {
	return &JWTVerifier{
		Resource: resource,
		Issuers:  []string{"https://auth.example.com"},
		Keys:     s.keys(),
		Now:      func() time.Time { return now },
	}
}

func TestValidTokenIsAccepted(t *testing.T) {
	s := newSigner(t)
	for _, algorithm := range []struct{ alg, kid string }{{"RS256", "rsa-1"}, {"ES256", "ec-1"}} {
		t.Run(algorithm.alg, func(t *testing.T) {
			claims, err := verifier(s).Verify(context.Background(), s.sign(t, algorithm.alg, algorithm.kid, goodClaims()))
			if err != nil {
				t.Fatal(err)
			}
			if claims.Subject != "user-1" || !claims.HasScope("mcp:read") {
				t.Errorf("claims = %+v", claims)
			}
		})
	}
}

// The whole reason this package exists: a perfectly valid token, correctly
// signed by a trusted issuer, issued for another service.
func TestATokenForAnotherResourceIsRefused(t *testing.T) {
	s := newSigner(t)
	claims := goodClaims()
	claims["aud"] = "https://another-service.example.com"

	_, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", claims))
	if !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("err = %v, want ErrWrongAudience: this is the confused deputy", err)
	}
}

// aud is allowed to be an array, and a verifier that only handles the string
// form quietly fails open or closed depending on how it was written.
func TestAudienceIsAcceptedInBothJSONForms(t *testing.T) {
	s := newSigner(t)

	array := goodClaims()
	array["aud"] = []string{"https://other.example.com", resource}
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", array)); err != nil {
		t.Errorf("an array audience containing this resource was refused: %v", err)
	}

	missing := goodClaims()
	missing["aud"] = []string{"https://other.example.com"}
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", missing)); !errors.Is(err, ErrWrongAudience) {
		t.Errorf("err = %v, want ErrWrongAudience", err)
	}
}

func TestAlgorithmConfusionIsRefused(t *testing.T) {
	s := newSigner(t)

	// "none": the attacker simply drops the signature.
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "none", "rsa-1", goodClaims())); !errors.Is(err, ErrBadSignature) {
		t.Errorf("alg=none: err = %v, want ErrBadSignature", err)
	}

	// HS256 signed with the public key material as the shared secret: the
	// classic confusion attack against a verifier that trusts the header's alg.
	signed := segment(map[string]string{"alg": "HS256", "kid": "rsa-1"}) + "." + segment(goodClaims())
	mac := hmac.New(sha256.New, s.rsaKey.PublicKey.N.Bytes())
	mac.Write([]byte(signed))
	forged := signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	_, err := verifier(s).Verify(context.Background(), forged)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("HS256 forgery: err = %v, want ErrBadSignature", err)
	}
	if !strings.Contains(err.Error(), "confusion") {
		t.Errorf("the refusal does not name the attack: %v", err)
	}
}

func TestExpiryAndNotBefore(t *testing.T) {
	s := newSigner(t)

	expired := goodClaims()
	expired["exp"] = now.Add(-2 * time.Hour).Unix()
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", expired)); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}

	future := goodClaims()
	future["nbf"] = now.Add(time.Hour).Unix()
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", future)); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("err = %v, want ErrNotYetValid", err)
	}

	// A token with no expiry is a password, not a token.
	eternal := goodClaims()
	delete(eternal, "exp")
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", eternal)); !errors.Is(err, ErrMalformedToken) {
		t.Errorf("err = %v, want a refusal for a token that never expires", err)
	}

	// Small clock differences between servers must not lock users out.
	barely := goodClaims()
	barely["exp"] = now.Add(-30 * time.Second).Unix()
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", barely)); err != nil {
		t.Errorf("a token 30s past expiry was refused despite the skew allowance: %v", err)
	}
}

func TestUnknownIssuerAndUnknownKey(t *testing.T) {
	s := newSigner(t)

	foreign := goodClaims()
	foreign["iss"] = "https://evil.example.com"
	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", foreign)); !errors.Is(err, ErrUnknownIssuer) {
		t.Errorf("err = %v, want ErrUnknownIssuer", err)
	}

	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "unknown-kid", goodClaims())); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want a refusal for an unknown key id", err)
	}
}

func TestMalformedTokens(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	for name, token := range map[string]string{
		"empty":        "",
		"two segments": "a.b",
		"not base64":   "!!!.!!!.!!!",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), token); err == nil {
				t.Error("accepted")
			}
		})
	}
}
