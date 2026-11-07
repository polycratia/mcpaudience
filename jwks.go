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
// The cache is not a TTL. Rotation does not wait for one — an issuer signs with
// a new key the moment it publishes it — so what asks for a fetch is a token
// naming a key id the copy in memory does not hold, and MinRefresh is what
// stops a stream of invented key ids from becoming a stream of requests at the
// issuer. Nothing on the request path expires a key id the copy does hold:
// CacheFor is the period Start refreshes on, and MaxStale is the one age the
// request path reads, past which a copy nobody has confirmed stops answering.
type JWKS struct {
	// URL of the key set document. It has to be https outside localhost.
	URL string
	// Client used for the fetch. Defaults to one with a 10s timeout.
	Client *http.Client
	// CacheFor is the period Start refreshes the set on when it is given none.
	// Defaults to 15 minutes.
	//
	// It is not a staleness check: a key id the copy in memory holds is answered
	// from it however long ago the set was fetched. A timer on the request path
	// bought nothing it did not also charge for. Rotation does not wait for it —
	// which is why an unknown key id refetches — so its lapse made whichever
	// token happened to arrive next pay for a fetch without making the copy any
	// more current for the key id that token already named. What a server wants
	// instead is a schedule of its own, and this is that schedule's period.
	CacheFor time.Duration
	// MinRefresh is the shortest gap between two fetches an arriving token asks
	// for, whatever about that token asks for one. Defaults to 30 seconds.
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
	//
	// It does not bound a refresh the server makes on a schedule of its own:
	// Refresh fetches whatever the interval would have said, because a schedule
	// is already its own bound. The attempt it makes is still recorded, so the
	// requests arriving behind it read it like any other.
	//
	// The failures carry the interval with them, so a 503 built on one names the
	// wait this cache is holding rather than a fixed guess: what is left of the
	// interval when a fetch was declined, and the whole of it when the fetch
	// that just failed is what started it.
	MinRefresh time.Duration
	// MaxStale bounds how long the last good set goes on answering once it can
	// no longer be refreshed. It is measured from the fetch that produced the
	// copy in memory, so the value set here is the oldest a key may be when it
	// verifies a signature. Zero, the default, is no bound: an issuer being
	// unreachable is not evidence that the key it published stopped being its
	// key, and the tokens it signed expire on their own.
	//
	// Setting it is the other reading of the same fact. A key the issuer has
	// since retired keeps verifying tokens here for as long as the copy in
	// memory answers, so a server that would rather refuse than verify against
	// a set it can no longer confirm gives that copy an expiry date. It is the
	// one age the request path reads: past the bound, a token naming a key the
	// copy holds asks the issuer to confirm it, and when the issuer cannot be
	// reached the cache answers ErrUnavailable — a 503 and an interval to wait,
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
	// KeyID is the key id whose absence triggered the fetch, or whose key the
	// copy in memory may no longer answer for unconfirmed. It is empty when no
	// token triggered it: a Refresh made on the server's own schedule.
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

// Key returns the public key published under kid, fetching the set if the copy
// in memory does not name that key id, or if it was fetched longer than
// MaxStale allows it to answer for without being confirmed.
//
// A fetch that fails with no copy of the set in memory is ErrUnavailable rather
// than an unknown key: the issuer was never reached, so nothing has been
// learned about the token that named this key id. A copy that was fetched
// longer than MaxStale ago answers the same way, for the same reason.
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

// Refresh fetches the key set now, for a server that would rather keep the copy
// in memory warm on a schedule of its own than meet a rotation on the request
// that needs it.
//
// MinRefresh does not apply here. The interval exists so that the fetches
// arriving tokens ask for cannot multiply with those tokens — a stream of
// invented key ids becoming a stream of requests at the issuer — and a caller
// with a ticker is already bounded by its own period, which is the thing to
// tune instead. The attempt is still recorded, before the request goes out, so
// a scheduled fetch that has just happened or just failed holds the request
// path off exactly as one an arriving token triggered would: the interval is
// spent by the attempt, whoever made it.
//
// It takes the same lock the request path holds across its fetch, so a
// scheduled refresh and a rotation an arriving token found do not both go out,
// and OnRefresh is reported on this caller's goroutine with no key id, because
// no token asked for this one.
func (j *JWKS) Refresh(ctx context.Context) error {
	if err := j.checkURL(); err != nil {
		return err
	}

	fetch, err := j.scheduledRefresh(ctx)
	if fetch != nil && j.OnRefresh != nil {
		j.OnRefresh(*fetch)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return nil
}

// Start runs Refresh on a ticker until the returned stop function is called or
// ctx is done. It is the schedule Refresh talks about, written out: a server
// that would rather keep the copy in memory warm than meet a rotation on the
// request that needs it writes this goroutine either way.
//
// every is the period. Zero is CacheFor, which is what that setting is — the
// schedule this cache is refreshed on, since nothing on the request path
// expires a key id the copy in memory holds. MinRefresh does not bound these
// fetches — the period already does — so the period is what to tune when the
// issuer should be asked less often.
//
// Nothing is fetched before the first tick, and nothing needs to be: the
// request path still fetches on demand, so starting the ticker is not a step a
// server has to finish before it can answer anything. The error is the key set
// URL being one no fetch would accept, so that is learned at startup rather
// than from a goroutine failing quietly once a period.
//
// stop ends the ticker and waits for a fetch in flight to return, cancelling
// its request, so a server that has shut down is not still asking its issuer
// for keys. It can be called more than once. A scheduled fetch that failed has
// no caller left to return the failure to, so OnRefresh is where one is
// noticed.
func (j *JWKS) Start(ctx context.Context, every time.Duration) (func(), error) {
	if err := j.checkURL(); err != nil {
		return nil, err
	}
	if every <= 0 {
		every = j.cacheFor()
	}

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() != nil {
					// A tick and a stop can both be ready. Fetching on a
					// cancelled context would fail at once and still spend
					// MinRefresh for the requests arriving behind it.
					return
				}
				_ = j.Refresh(ctx)
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}, nil
}

func (j *JWKS) scheduledRefresh(ctx context.Context) (*KeySetRefresh, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.refresh(ctx, "", ownSchedule)
}

// key does the lookup and hands back the fetch it made, if it made one, for the
// caller to report once the lock is gone.
func (j *JWKS) key(ctx context.Context, kid string) (crypto.PublicKey, *KeySetRefresh, error) {
	// The lock is held across the fetch, so a burst of requests arriving on a
	// rotation makes one request at the issuer rather than one each.
	j.mu.Lock()
	defer j.mu.Unlock()

	// A key id the copy in memory holds is answered from it, however long ago
	// that copy was fetched: asking the issuer again on a schedule is the
	// server's own business, and MaxStale is the only age read here.
	cached, known := j.keys[kid]
	if known && !j.beyondMaxStale() {
		return cached, nil, nil
	}
	fetch, err := j.refresh(ctx, kid, arrivingToken)
	if err != nil {
		if len(j.keys) == 0 {
			return nil, fetch, fmt.Errorf("%w: no key set from %s is held: %w", ErrUnavailable, j.URL, err)
		}
		if j.beyondMaxStale() {
			// The copy in memory outlived what it was allowed to answer for, so
			// there is no verdict left to give: whether the issuer still
			// publishes this key is no longer known.
			return nil, fetch, fmt.Errorf("%w: the key set from %s was last fetched %s ago, past the %s it may answer for without being confirmed: %w",
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

// tooSoon is the refusal MinRefresh makes. It carries what is left of the
// interval, so a 503 built on top of it can name the wait this cache is
// actually holding rather than a fixed guess.
type tooSoon struct {
	since    time.Duration
	interval time.Duration
}

func (t tooSoon) Error() string {
	return fmt.Sprintf("the key set was fetched %s ago and is not fetched again more than once every %s",
		t.since.Round(time.Second), t.interval)
}

func (t tooSoon) RetryAfter() time.Duration { return t.interval - t.since }

// unreachable is a fetch that went out and did not produce a set. The attempt
// was recorded before the request, so the next fetch is held off for the whole
// interval, and that — not a fixed guess — is the wait a 503 built on this
// failure should name.
type unreachable struct {
	err      error
	interval time.Duration
}

func (u unreachable) Error() string { return u.err.Error() }

func (u unreachable) Unwrap() error { return u.err }

func (u unreachable) RetryAfter() time.Duration { return u.interval }

// trigger is what asked for a fetch, which is what decides whether MinRefresh
// has anything to say about it.
type trigger bool

const (
	arrivingToken trigger = false
	ownSchedule   trigger = true
)

func (j *JWKS) refresh(ctx context.Context, kid string, asked trigger) (*KeySetRefresh, error) {
	now := j.now()
	if since := now.Sub(j.attempted); asked == arrivingToken && !j.attempted.IsZero() && since < j.minRefresh() {
		return nil, tooSoon{since: since, interval: j.minRefresh()}
	}
	// Recorded before the fetch rather than after it, so an attempt that fails
	// or is abandoned spends the interval too — including one the interval did
	// not hold back, because what the request path reads is the attempt.
	j.attempted = now
	fetch := &KeySetRefresh{KeyID: kid, At: now}

	body, err := j.get(ctx)
	if err != nil {
		fetch.Err = err
		return fetch, unreachable{err: err, interval: j.minRefresh()}
	}
	keys, skipped, err := parseKeySet(body)
	if err != nil {
		err = fmt.Errorf("%s: %v", j.URL, err)
		fetch.Err = err
		return fetch, unreachable{err: err, interval: j.minRefresh()}
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

// beyondMaxStale reports whether the copy in memory is older than MaxStale lets
// it keep answering for. The age is measured from the fetch that produced it,
// so the bound configured is the oldest a key may be when it verifies a
// signature rather than one term of a sum.
func (j *JWKS) beyondMaxStale() bool {
	if j.MaxStale <= 0 || j.fetched.IsZero() {
		return false
	}
	return j.now().Sub(j.fetched) > j.MaxStale
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
