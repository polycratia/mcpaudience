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
	"maps"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"slices"
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
	//
	// The interval is spent by the attempt rather than by its result: it is
	// recorded before the request goes out, so a fetch that failed — or one
	// abandoned because the request whose token triggered it was cancelled —
	// holds the next one off for the full interval, exactly as a fetch that
	// succeeded does. That is the case the interval exists for: an issuer that
	// is down or slow is where refetching on every arriving token does the most
	// damage. The cost is that recovery is not immediate — the last good set
	// keeps answering until the interval lapses, and a cache that never held one
	// answers ErrUnavailable until then.
	MinRefresh time.Duration
	// MaxStale bounds how long the last good set goes on answering once it can
	// no longer be refreshed. It is measured past the point the set went stale,
	// so a copy in memory answers for CacheFor and then for MaxStale beyond it.
	// Zero, the default, is no bound: an issuer being unreachable is not
	// evidence that the key it published stopped being its key, and the tokens
	// it signed expire on their own.
	//
	// Setting it is the other reading of the same fact. A key the issuer has
	// since retired keeps verifying tokens here for as long as the copy in
	// memory answers, so a server that would rather refuse than verify against
	// a set it can no longer confirm gives that copy an expiry date. Past the
	// bound the cache answers ErrUnavailable — a 503 and an interval to wait,
	// not a verdict on the token, because the signature still has not been
	// checked against anything current.
	MaxStale time.Duration
	// OnRefresh, if set, is called once for every fetch of the key set that
	// actually happens: not for a key answered from memory, and not for one
	// MinRefresh declined to make.
	//
	// Where it runs is what decides what belongs in it. It runs on the
	// goroutine of the request whose token triggered the fetch, so whatever it
	// does is part of that request's latency. It runs after Key has released
	// j.mu, the lock held across the fetch, so it can read this cache without
	// deadlocking and a slow callback does not hold back the requests queued
	// behind a rotation. And it is handed no context: the caller's belongs to a
	// request that is about to be answered, so anything the callback sends
	// elsewhere needs a context and a deadline of its own.
	OnRefresh func(KeySetRefresh)
	// Now is injectable for tests.
	Now func() time.Time

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	skipped   map[string]string
	fetched   time.Time
	attempted time.Time
}

// KeySetRefresh is one fetch of the key set, as reported to OnRefresh.
type KeySetRefresh struct {
	// KeyID is the key id whose absence or staleness triggered the fetch.
	KeyID string
	// KeyIDs are the usable key ids the fetched set carried, sorted. It is
	// empty when the fetch produced no set.
	KeyIDs []string
	// At is when the fetch was made, on this cache's clock.
	At time.Time
	// Err is why the fetch produced no new set. It is not a verdict on the
	// token that triggered it: the last good set keeps answering.
	Err error
}

const maxKeySetBytes = 1 << 20

// Key returns the public key published under kid, fetching the set if it is not
// held, has gone stale, or does not name that key id yet.
//
// A fetch that fails with no copy of the set in memory is ErrUnavailable rather
// than an unknown key: the issuer was never reached, so nothing has been
// learned about the token that named this key id. A copy that has gone past
// MaxStale answers the same way, for the same reason.
func (j *JWKS) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if err := j.checkURL(); err != nil {
		return nil, err
	}

	key, fetch, err := j.key(ctx, kid)
	if fetch != nil && j.OnRefresh != nil {
		j.OnRefresh(*fetch)
	}
	return key, err
}

// key does the lookup and hands back the fetch it made, if it made one, for the
// caller to report once the lock is gone.
func (j *JWKS) key(ctx context.Context, kid string) (crypto.PublicKey, *KeySetRefresh, error) {
	// The lock is held across the fetch, so a burst of requests arriving on a
	// rotation makes one request at the issuer rather than one each.
	j.mu.Lock()
	defer j.mu.Unlock()

	cached, known := j.keys[kid]
	if known && !j.stale() {
		return cached, nil, nil
	}
	fetch, err := j.refresh(ctx, kid)
	if err != nil {
		beyond := j.beyondMaxStale()
		if known && !beyond {
			// An issuer being unreachable is not evidence that the key it
			// published stopped being its key. Tokens still expire on their own.
			return cached, fetch, nil
		}
		if len(j.keys) == 0 {
			return nil, fetch, fmt.Errorf("%w: no key set from %s is held: %v", ErrUnavailable, j.URL, err)
		}
		if beyond {
			// The copy in memory outlived what it was allowed to answer for, so
			// there is no verdict left to give: whether the issuer still
			// publishes this key is no longer known.
			return nil, fetch, fmt.Errorf("%w: the key set from %s was last fetched %s ago, past the %s it may be served stale for: %v",
				ErrUnavailable, j.URL, j.now().Sub(j.fetched).Round(time.Second), j.MaxStale, err)
		}
		// A set is held and does not name this kid, which is a verdict rather
		// than an outage, whatever the failed refresh was about.
		return nil, fetch, fmt.Errorf("no key for kid %q: %v", kid, err)
	}
	if key, ok := j.keys[kid]; ok {
		return key, fetch, nil
	}
	if reason, ok := j.skipped[kid]; ok {
		return nil, fetch, fmt.Errorf("the key set lists kid %q but it cannot be used: %s", kid, reason)
	}
	return nil, fetch, fmt.Errorf("no key for kid %q in the key set at %s", kid, j.URL)
}

func (j *JWKS) refresh(ctx context.Context, kid string) (*KeySetRefresh, error) {
	now := j.now()
	if since := now.Sub(j.attempted); !j.attempted.IsZero() && since < j.minRefresh() {
		return nil, fmt.Errorf("the key set was fetched %s ago and is not fetched again more than once every %s",
			since.Round(time.Second), j.minRefresh())
	}
	// Recorded before the fetch rather than after it, so an attempt that fails
	// or is abandoned spends the interval too.
	j.attempted = now
	fetch := &KeySetRefresh{KeyID: kid, At: now}

	body, err := j.get(ctx)
	if err != nil {
		fetch.Err = err
		return fetch, err
	}
	keys, skipped, err := parseKeySet(body)
	if err != nil {
		err = fmt.Errorf("%s: %v", j.URL, err)
		fetch.Err = err
		return fetch, err
	}
	j.keys, j.skipped, j.fetched = keys, skipped, now
	fetch.KeyIDs = slices.Sorted(maps.Keys(keys))
	return fetch, nil
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

// beyondMaxStale reports whether the set in memory has gone longer without a
// successful fetch than MaxStale allows it to keep answering for.
func (j *JWKS) beyondMaxStale() bool {
	if j.MaxStale <= 0 || j.fetched.IsZero() {
		return false
	}
	return j.now().Sub(j.fetched) > j.cacheFor()+j.MaxStale
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
