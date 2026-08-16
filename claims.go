package mcpaudience

import (
	"encoding/json"
	"errors"
	"fmt"
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
	granted := c.Scopes()
	for _, scope := range required {
		if !slices.Contains(granted, scope) {
			return false
		}
	}
	return true
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
	return slices.Contains([]string(a), resource)
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

// checkStandard applies the checks every verifier owes, whatever it used to
// authenticate the token.
//
// The audience check is the one that cannot be optional: without it this server
// accepts any valid token from a trusted issuer, including one a user granted
// to a completely different service, and becomes that service's deputy.
func checkStandard(claims Claims, resource string, issuers []string, now time.Time, skew time.Duration) error {
	if !claims.Active {
		return ErrInactive
	}
	if len(issuers) > 0 && !slices.Contains(issuers, claims.Issuer) {
		return fmt.Errorf("%w: %q", ErrUnknownIssuer, claims.Issuer)
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
