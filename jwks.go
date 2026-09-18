package mcpaudience

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KeySource hands back the public key a token's key id names. It is the seam
// between keys a server was configured with and keys it has to go and fetch.
type KeySource interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// JWKS is an authorization server's published key set, fetched over HTTP and
// held in memory.
//
// The cache is not a plain TTL, because rotation does not wait for one. An
// issuer signs with a new key the moment it publishes it, so an unknown key id
// refetches the set rather than refusing tokens until the TTL happens to lapse.
// MinRefresh is what stops that from turning a stream of invented key ids into
// a stream of requests at the issuer.
type JWKS struct {
	// URL of the key set document. It has to be https outside localhost.
	URL string
	// Client used for the fetch. Defaults to one with a 10s timeout.
	Client *http.Client
	// CacheFor is how long a fetched set is served before it is fetched again.
	// Defaults to 15 minutes.
	CacheFor time.Duration
	// MinRefresh is the shortest gap between two fetches, whatever asks for one.
	// Defaults to 30 seconds.
	MinRefresh time.Duration
	// Now is injectable for tests.
	Now func() time.Time

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	skipped   map[string]string
	fetched   time.Time
	attempted time.Time
}

const maxKeySetBytes = 1 << 20

// Key returns the public key published under kid, fetching the set if it is not
// held, has gone stale, or does not name that key id yet.
func (j *JWKS) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if err := j.checkURL(); err != nil {
		return nil, err
	}

	// The lock is held across the fetch, so a burst of requests arriving on a
	// rotation makes one request at the issuer rather than one each.
	j.mu.Lock()
	defer j.mu.Unlock()

	cached, known := j.keys[kid]
	if known && !j.stale() {
		return cached, nil
	}
	if err := j.refresh(ctx); err != nil {
		if known {
			// An issuer being unreachable is not evidence that the key it
			// published stopped being its key. Tokens still expire on their own.
			return cached, nil
		}
		return nil, fmt.Errorf("no key for kid %q: %v", kid, err)
	}
	if key, ok := j.keys[kid]; ok {
		return key, nil
	}
	if reason, ok := j.skipped[kid]; ok {
		return nil, fmt.Errorf("the key set lists kid %q but it cannot be used: %s", kid, reason)
	}
	return nil, fmt.Errorf("no key for kid %q in the key set at %s", kid, j.URL)
}

func (j *JWKS) refresh(ctx context.Context) error {
	now := j.now()
	if since := now.Sub(j.attempted); !j.attempted.IsZero() && since < j.minRefresh() {
		return fmt.Errorf("the key set was fetched %s ago and is not fetched again more than once every %s",
			since.Round(time.Second), j.minRefresh())
	}
	j.attempted = now

	body, err := j.get(ctx)
	if err != nil {
		return err
	}
	keys, skipped, err := parseKeySet(body)
	if err != nil {
		return fmt.Errorf("%s: %v", j.URL, err)
	}
	j.keys, j.skipped, j.fetched = keys, skipped, now
	return nil
}

func (j *JWKS) get(ctx context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/json")

	response, err := j.client().Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %v", j.URL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: the issuer answered %d", j.URL, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxKeySetBytes))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", j.URL, err)
	}
	return body, nil
}

func (j *JWKS) checkURL() error {
	raw := strings.TrimSpace(j.URL)
	if raw == "" {
		return fmt.Errorf("no key set URL configured")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("key set URL %q is not an absolute URL", j.URL)
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return fmt.Errorf("key set URL %q must use https: a key set an attacker on the path can replace verifies the attacker's tokens", j.URL)
	}
	return nil
}

func (j *JWKS) stale() bool {
	return j.fetched.IsZero() || j.now().Sub(j.fetched) >= j.cacheFor()
}

func (j *JWKS) client() *http.Client {
	if j.Client != nil {
		return j.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (j *JWKS) cacheFor() time.Duration {
	if j.CacheFor > 0 {
		return j.CacheFor
	}
	return 15 * time.Minute
}

func (j *JWKS) minRefresh() time.Duration {
	if j.MinRefresh > 0 {
		return j.MinRefresh
	}
	return 30 * time.Second
}

func (j *JWKS) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

type jwk struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Curve     string `json:"crv"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// parseKeySet keeps the keys it can use and remembers why it dropped the rest,
// so a token naming a dropped key id is refused with the reason rather than
// with "unknown".
func parseKeySet(body []byte) (map[string]crypto.PublicKey, map[string]string, error) {
	var document struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, nil, fmt.Errorf("the key set is not JSON: %v", err)
	}

	keys := make(map[string]crypto.PublicKey)
	skipped := make(map[string]string)
	var problems []string
	for _, entry := range document.Keys {
		name := entry.KeyID
		if name == "" {
			name = "(no kid)"
		}
		key, err := entry.publicKey()
		if err != nil {
			problems = append(problems, name+": "+err.Error())
			if entry.KeyID != "" {
				skipped[entry.KeyID] = err.Error()
			}
			continue
		}
		if entry.KeyID == "" {
			problems = append(problems, "(no kid): a key no token can name")
			continue
		}
		keys[entry.KeyID] = key
	}
	if len(keys) == 0 {
		if len(problems) == 0 {
			return nil, nil, fmt.Errorf("the key set carries no keys")
		}
		return nil, nil, fmt.Errorf("the key set carries no usable key: %s", strings.Join(problems, "; "))
	}
	return keys, skipped, nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	if k.Use != "" && k.Use != "sig" {
		return nil, fmt.Errorf("use %q is not for signatures", k.Use)
	}
	switch k.Algorithm {
	case "none", "HS256", "HS384", "HS512":
		return nil, fmt.Errorf("alg %q has no place in a public key set", k.Algorithm)
	}

	switch k.KeyType {
	case "RSA":
		modulus, err := decodeBigInt("n", k.Modulus)
		if err != nil {
			return nil, err
		}
		exponent, err := decodeBigInt("e", k.Exponent)
		if err != nil {
			return nil, err
		}
		if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64() > math.MaxInt32 {
			return nil, fmt.Errorf("public exponent %s is out of range", exponent)
		}
		if modulus.BitLen() < 2048 {
			return nil, fmt.Errorf("a %d-bit RSA key is too small to trust a signature from", modulus.BitLen())
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
	case "EC":
		if k.Curve != "P-256" {
			return nil, fmt.Errorf("curve %q: only P-256 is verified here, as ES256", k.Curve)
		}
		x, err := decodeCoordinate("x", k.X)
		if err != nil {
			return nil, err
		}
		y, err := decodeCoordinate("y", k.Y)
		if err != nil {
			return nil, err
		}
		point := append([]byte{4}, append(x, y...)...)
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("the point is not on P-256: %v", err)
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil
	case "oct":
		return nil, fmt.Errorf("a symmetric key published in a public key set is the algorithm-confusion attack with the secret handed over in advance")
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.KeyType)
	}
}

func decodeBigInt(field, value string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("%s is not base64url", field)
	}
	return new(big.Int).SetBytes(raw), nil
}

func decodeCoordinate(field, value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not base64url", field)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("%s is %d bytes, P-256 coordinates are 32", field, len(raw))
	}
	return raw, nil
}
