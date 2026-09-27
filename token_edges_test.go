package mcpaudience

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// signedWithAlg builds a token whose header names algorithm but whose signature
// is a genuine RS256 signature over it, so a refusal can only be about the
// algorithm the header asked for and not about bytes that do not add up.
func signedWithAlg(t *testing.T, s *signer, algorithm string, claims map[string]any) string {
	t.Helper()
	signed := segment(map[string]string{"alg": algorithm, "kid": "rsa-1", "typ": "JWT"}) + "." + segment(claims)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// unsignedToken is the attacker's alg=none: a perfectly formed payload with the
// signature segment left empty.
func unsignedToken(claims map[string]any) string {
	return segment(map[string]string{"alg": "none", "kid": "rsa-1", "typ": "JWT"}) + "." + segment(claims) + "."
}

// Every way a token can be wrong has to come back as the same kind of answer:
// 401, invalid_token, and the pointer to the document that says where a better
// token comes from. A client that gets a 500 or a 200 for any of these has no
// move left to make.
func TestEveryTokenEdgeCaseAnswersA401ThatPointsAtTheMetadata(t *testing.T) {
	s := newSigner(t)
	g := guard(verifier(s))

	expired := goodClaims()
	expired["exp"] = now.Add(-time.Hour).Unix()

	foreignAudience := goodClaims()
	foreignAudience["aud"] = "https://another-service.example.com"

	foreignIssuer := goodClaims()
	foreignIssuer["iss"] = "https://evil.example.com"

	future := goodClaims()
	future["nbf"] = now.Add(time.Hour).Unix()

	cases := map[string]string{
		"expired":        s.sign(t, "RS256", "rsa-1", expired),
		"wrong audience": s.sign(t, "RS256", "rsa-1", foreignAudience),
		"wrong issuer":   s.sign(t, "RS256", "rsa-1", foreignIssuer),
		"unknown kid":    s.sign(t, "RS256", "rsa-9", goodClaims()),
		"future nbf":     s.sign(t, "RS256", "rsa-1", future),
		"alg none":       unsignedToken(goodClaims()),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			response := call(g, okHandler(), "Bearer "+token)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", response.Code)
			}
			if strings.Contains(response.Body.String(), "served for") {
				t.Fatal("the handler ran")
			}
			challenge := response.Header().Get("WWW-Authenticate")
			if !strings.Contains(challenge, `error="invalid_token"`) {
				t.Errorf("challenge = %q, want invalid_token", challenge)
			}
			if !strings.Contains(challenge, `resource_metadata="`+resource+MetadataPath+`"`) {
				t.Errorf("challenge = %q, want the metadata pointer", challenge)
			}
		})
	}
}

// Skew is a tolerance, not a grace period: it moves the boundary by exactly the
// seconds it is given, and a token further past expiry than that is expired.
func TestTheExpiryBoundaryIsTheSkewAndNothingMore(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	v.Skew = 30 * time.Second

	cases := map[string]struct {
		offset  time.Duration
		expired bool
	}{
		"an hour left":           {time.Hour, false},
		"expiring this instant":  {0, false},
		"a second past":          {-time.Second, false},
		"at the edge of the skew": {-30 * time.Second, false},
		"a second beyond it":     {-31 * time.Second, true},
		"an hour ago":            {-time.Hour, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			claims := goodClaims()
			claims["exp"] = now.Add(c.offset).Unix()

			_, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", claims))
			if c.expired {
				if !errors.Is(err, ErrExpired) {
					t.Fatalf("err = %v, want ErrExpired", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want the token accepted inside the skew", err)
			}
		})
	}
}

// The same allowance in the other direction: a token minted a moment ago by a
// server running slightly fast must not read as "not valid yet", and one dated
// properly in the future must.
func TestTheNotBeforeBoundaryIsTheSkewInTheOtherDirection(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	v.Skew = 30 * time.Second

	cases := map[string]struct {
		offset time.Duration
		early  bool
	}{
		"an hour ago":             {-time.Hour, false},
		"this instant":            {0, false},
		"at the edge of the skew":  {30 * time.Second, false},
		"a second beyond it":      {31 * time.Second, true},
		"an hour away":            {time.Hour, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			claims := goodClaims()
			claims["nbf"] = now.Add(c.offset).Unix()

			_, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", claims))
			if c.early {
				if !errors.Is(err, ErrNotYetValid) {
					t.Fatalf("err = %v, want ErrNotYetValid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want the token accepted", err)
			}
		})
	}

	// nbf is optional, and a token without one is valid from the moment it was
	// signed rather than never.
	without := goodClaims()
	delete(without, "nbf")
	if _, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", without)); err != nil {
		t.Errorf("a token with no nbf was refused: %v", err)
	}
}

// Issuer identifiers are compared as exact strings. Forgiving a trailing slash
// or a case difference here would mean trusting a URL the allow-list does not
// actually name.
func TestIssuerComparisonIsExact(t *testing.T) {
	s := newSigner(t)
	for name, issuer := range map[string]string{
		"another server": "https://evil.example.com",
		"trailing slash": "https://auth.example.com/",
		"uppercase host": "https://AUTH.example.com",
		"a path below":   "https://auth.example.com/tenant-2",
		"none at all":    "",
	} {
		t.Run(name, func(t *testing.T) {
			claims := goodClaims()
			claims["iss"] = issuer

			_, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", claims))
			if !errors.Is(err, ErrUnknownIssuer) {
				t.Fatalf("err = %v, want ErrUnknownIssuer", err)
			}
			if !strings.Contains(err.Error(), issuer) {
				t.Errorf("err = %v, want it to name the issuer that was refused", err)
			}
		})
	}
}

// An empty allow-list accepts any issuer, which is the one field here that can
// be left open. What it cannot open is the audience: a token from an issuer
// nobody vouched for still has to have been minted for this server.
func TestWithNoIssuerAllowListTheAudienceIsStillTheBackstop(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	v.Issuers = nil

	stranger := goodClaims()
	stranger["iss"] = "https://someone-else.example.com"
	if _, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", stranger)); err != nil {
		t.Errorf("err = %v, want an unlisted issuer accepted when no list is configured", err)
	}

	stranger["aud"] = "https://another-service.example.com"
	if _, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", stranger)); !errors.Is(err, ErrWrongAudience) {
		t.Errorf("err = %v, want ErrWrongAudience", err)
	}
}

// A key id nobody published is refused rather than resolved against whatever
// key happens to be at hand: trying the keys held until one verifies is how a
// retired key keeps signing valid tokens.
func TestAnUnknownKeyIDIsRefusedRatherThanSearchedFor(t *testing.T) {
	s := newSigner(t)

	_, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-9", goodClaims()))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	if !strings.Contains(err.Error(), "rsa-9") {
		t.Errorf("err = %v, want it to name the key id that could not be found", err)
	}
}

// A token that names no key id at all leaves nothing to look up. Picking a key
// anyway works right up until a second one is published.
func TestATokenThatNamesNoKeyIsRefusedRatherThanGuessed(t *testing.T) {
	s := newSigner(t)

	if _, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "", goodClaims())); !errors.Is(err, ErrBadSignature) {
		t.Errorf("keys held in memory: err = %v, want ErrBadSignature", err)
	}

	issuer := newKeyServer(t, rsaJWK("rsa-1", &s.rsaKey.PublicKey))
	v := keySetVerifier(&JWKS{URL: issuer.url, Now: func() time.Time { return now }})

	if _, err := v.Verify(context.Background(), s.sign(t, "RS256", "", goodClaims())); !errors.Is(err, ErrBadSignature) {
		t.Errorf("key set: err = %v, want ErrBadSignature", err)
	}
	if got := issuer.count(); got != 0 {
		t.Errorf("the issuer was fetched %d times for a key the token did not name, want none", got)
	}
}

// The header's alg is the attacker's field, so it selects nothing: it is
// checked against what this package verifies and refused by name otherwise.
func TestTheHeaderAlgorithmDoesNotChooseTheVerification(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)

	for name, c := range map[string]struct{ algorithm, says string }{
		"none":            {"none", "trust me"},
		"absent":          {"", "trust me"},
		"HS256":           {"HS256", "confusion"},
		"HS512":           {"HS512", "confusion"},
		"RS512":           {"RS512", "unsupported"},
		"ES384":           {"ES384", "unsupported"},
		"lowercase rs256": {"rs256", "unsupported"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), signedWithAlg(t, s, c.algorithm, goodClaims()))
			if !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature", err)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("err = %v, want it to say %q", err, c.says)
			}
		})
	}
}

// Nothing in the payload is believed before the signature is. A token signed
// with a key this server does not hold is refused for the signature, and the
// claims it carries are not reported back as though they had been read.
func TestClaimsAreNotJudgedBeforeTheSignatureIs(t *testing.T) {
	held, attacker := newSigner(t), newSigner(t)

	claims := goodClaims()
	claims["exp"] = now.Add(-time.Hour).Unix()
	claims["aud"] = "https://another-service.example.com"
	claims["iss"] = "https://evil.example.com"

	_, err := verifier(held).Verify(context.Background(), attacker.sign(t, "RS256", "rsa-1", claims))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
	if strings.Contains(err.Error(), "another-service.example.com") || strings.Contains(err.Error(), "evil.example.com") {
		t.Errorf("err = %v, want it to say nothing about claims that were never verified", err)
	}
}
