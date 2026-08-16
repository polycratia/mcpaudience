package mcpaudience

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Verifier turns a bearer token into claims, or refuses it.
type Verifier interface {
	Verify(ctx context.Context, token string) (Claims, error)
}

// JWTVerifier validates a signed JWT against public keys it already holds.
type JWTVerifier struct {
	// Resource is this server's canonical URI: the value a token's audience
	// must contain.
	Resource string
	// Issuers the server trusts. Empty means any issuer, which is almost never
	// what anyone wants.
	Issuers []string
	// Keys by key id. Only public keys belong here.
	Keys map[string]crypto.PublicKey
	// Skew tolerated on expiry and not-before. Defaults to 60s.
	Skew time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// Verify checks the signature, then everything a signature does not say.
func (v *JWTVerifier) Verify(_ context.Context, token string) (Claims, error) {
	if strings.TrimSpace(token) == "" {
		return Claims{}, ErrNoToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected three segments", ErrMalformedToken)
	}

	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header: %v", ErrMalformedToken, err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, fmt.Errorf("%w: header: %v", ErrMalformedToken, err)
	}

	key, ok := v.Keys[header.KeyID]
	if !ok {
		return Claims{}, fmt.Errorf("%w: no key for kid %q", ErrBadSignature, header.KeyID)
	}
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature: %v", ErrMalformedToken, err)
	}

	signed := parts[0] + "." + parts[1]
	if err := verifySignature(header.Algorithm, key, signed, signature); err != nil {
		return Claims{}, err
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload: %v", ErrMalformedToken, err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, fmt.Errorf("%w: payload: %v", ErrMalformedToken, err)
	}
	claims.Active = true // a JWT has no active flag; it is live until it expires

	return claims, checkStandard(claims, v.Resource, v.Issuers, v.now(), v.skew())
}

// verifySignature refuses everything except the two asymmetric algorithms this
// package supports.
//
// The refusals matter more than the support. "none" is an algorithm that means
// "trust me". An HMAC algorithm against a key set of public keys is the
// algorithm-confusion attack: the attacker signs with the public key as the
// shared secret, and a verifier that dispatches on the header's alg alone
// accepts it.
func verifySignature(algorithm string, key crypto.PublicKey, signed string, signature []byte) error {
	digest := sha256.Sum256([]byte(signed))
	switch algorithm {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RS256 named for a %T key", ErrBadSignature, key)
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("%w: %v", ErrBadSignature, err)
		}
		return nil
	case "ES256":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ES256 named for a %T key", ErrBadSignature, key)
		}
		if len(signature) != 64 {
			return fmt.Errorf("%w: ES256 signature must be 64 bytes, got %d", ErrBadSignature, len(signature))
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(ecKey, digest[:], r, s) {
			return ErrBadSignature
		}
		return nil
	case "none", "":
		return fmt.Errorf("%w: alg %q means \"trust me\"", ErrBadSignature, algorithm)
	case "HS256", "HS384", "HS512":
		return fmt.Errorf(
			"%w: symmetric alg %s against a public key set is the algorithm-confusion attack",
			ErrBadSignature, algorithm)
	default:
		return fmt.Errorf("%w: unsupported alg %q", ErrBadSignature, algorithm)
	}
}

func (v *JWTVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *JWTVerifier) skew() time.Duration {
	if v.Skew > 0 {
		return v.Skew
	}
	return time.Minute
}

func decodeSegment(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(segment)
}
