package mcpaudience

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Claims is the part of a token this package makes decisions on.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	Scope     string   `json:"scope"`
	ClientID  string   `json:"client_id"`
	TokenID   string   `json:"jti"`
	// Active is used by introspection responses; a JWT has no such field and
	// leaves it true.
	Active bool `json:"active"`
}

// Scopes splits the space-delimited scope claim.
func (c Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// HasScope reports whether every required scope is present.
func (c Claims) HasScope(required ...string) bool {
	return len(c.MissingScopes(required...)) == 0
}

// MissingScopes returns the required scopes this token does not carry, in the
// order they were asked for. It is what turns a refusal into an instruction:
// a tool that requires four scopes and refuses over one of them can say which.
func (c Claims) MissingScopes(required ...string) []string {
	granted := c.Scopes()
	var missing []string
	for _, scope := range required {
		if !slices.Contains(granted, scope) {
			missing = append(missing, scope)
		}
	}
	return missing
}

// Audience is the aud claim, which JWT allows to be either a single string or
// an array of them. Modelling it as a plain string is the bug that makes an
// audience check silently pass: an array arrives, unmarshalling fails or yields
// empty, and "no audience" reads as "not for me" — or worse, as "fine".
type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("aud: expected a string or an array of strings")
	}
	*a = many
	return nil
}

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Contains reports whether the audience names this resource.
func (a Audience) Contains(resource string) bool {
	for _, value := range a {
		if sameResource(value, resource) {
			return true
		}
	}
	return false
}

// sameResource compares two resource identifiers on their canonical form.
//
// The two failure modes are opposite and both real. Comparing raw strings
// refuses a token that says HTTPS://MCP.Example.com:443 for a server that calls
// itself https://mcp.example.com, which is the same server by every rule the
// URI syntax has. Comparing loosely — prefixes, hosts by suffix, paths ignored —
// accepts tokens minted for a neighbour. So: scheme and host case-folded, a
// default port dropped, a trailing slash dropped, and everything else exact.
func sameResource(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	return canonicalResource(a) == canonicalResource(b)
}

func canonicalResource(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return raw
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Host)
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}

	canonical := scheme + "://" + host + strings.TrimSuffix(parsed.EscapedPath(), "/")
	if parsed.RawQuery != "" {
		canonical += "?" + parsed.RawQuery
	}
	if parsed.Fragment != "" {
		canonical += "#" + parsed.EscapedFragment()
	}
	return canonical
}

// Reasons a token is refused. They are distinguished because the WWW-
// Authenticate response says different things for each.
var (
	ErrNoToken        = errors.New("no bearer token presented")
	ErrMalformedToken = errors.New("token is malformed")
	ErrBadSignature   = errors.New("token signature does not verify")
	ErrUnknownIssuer  = errors.New("token was issued by an unrecognised authorization server")
	ErrWrongAudience  = errors.New("token was not issued for this resource")
	ErrExpired        = errors.New("token has expired")
	ErrNotYetValid    = errors.New("token is not valid yet")
	ErrInactive       = errors.New("token is not active")
	ErrMissingScope   = errors.New("token does not carry the required scope")
)

// ErrNoResource is a server fault rather than a bad token: without a resource
// identifier there is nothing to bind an audience to. It answers 500, because a
// 401 would blame the client for a mistake it cannot fix.
var ErrNoResource = errors.New("no resource identifier configured: audience binding cannot be skipped")

// ScopeError is a denial a caller can act on. A bare 403 says only that the
// request lost, which leaves four guesses on the table: wrong token, wrong
// tool, wrong user, or a server bug. This one names the tool that refused, the
// scopes it was missing, and what the token does carry instead.
type ScopeError struct {
	// Tool is the tool that refused. Empty means the whole server did.
	Tool string
	// Required is everything that tool asks for, Missing only the part this
	// token did not have. They differ, and reporting the first as if it were
	// the second sends people looking for scopes they already hold.
	Required []string
	Missing  []string
	Granted  []string
}

func (e *ScopeError) Error() string {
	subject := "this server"
	if e.Tool != "" {
		subject = fmt.Sprintf("tool %q", e.Tool)
	}
	carries := "no scopes at all"
	if len(e.Granted) > 0 {
		carries = strings.Join(e.Granted, " ")
	}
	return fmt.Sprintf("%s: %s needs %s; the token carries %s",
		ErrMissingScope, subject, strings.Join(e.Missing, " "), carries)
}

func (e *ScopeError) Unwrap() error { return ErrMissingScope }

// checkStandard applies the checks every verifier owes, whatever it used to
// authenticate the token.
//
// The audience check is the one that cannot be optional: without it this server
// accepts any valid token from a trusted issuer, including one a user granted
// to a completely different service, and becomes that service's deputy. There
// is no field that disables it and no value of one that skips it — an empty
// resource stops the server instead of opening it.
func checkStandard(claims Claims, resource string, issuers []string, now time.Time, skew time.Duration) error {
	if strings.TrimSpace(resource) == "" {
		return ErrNoResource
	}
	if !claims.Active {
		return ErrInactive
	}
	if len(issuers) > 0 && !slices.Contains(issuers, claims.Issuer) {
		return fmt.Errorf("%w: %q", ErrUnknownIssuer, claims.Issuer)
	}
	if len(claims.Audience) == 0 {
		return fmt.Errorf("%w: the token names no audience at all", ErrWrongAudience)
	}
	if !claims.Audience.Contains(resource) {
		return fmt.Errorf("%w: audience %v does not include %q", ErrWrongAudience, []string(claims.Audience), resource)
	}
	if claims.ExpiresAt == 0 {
		// A token that never expires is not a token, it is a password.
		return fmt.Errorf("%w: no expiry", ErrMalformedToken)
	}
	if now.Add(-skew).After(time.Unix(claims.ExpiresAt, 0)) {
		return ErrExpired
	}
	if claims.NotBefore != 0 && now.Add(skew).Before(time.Unix(claims.NotBefore, 0)) {
		return ErrNotYetValid
	}
	return nil
}
