package mcpaudience

import (
	"context"
	"net/http"
	"time"
)

// Principal is who a request is running as once the guard has verified it: the
// subject, the client holding the token, the issuer that minted it, and the
// scopes it carries.
//
// It is what a tool handler is given, and the token is what it is given
// instead of. A handler that can read the bearer token can also forward it,
// and a token spent on another service is the confused-deputy problem this
// package refuses at the door, arriving from the inside.
type Principal struct {
	// Subject is the user the token was issued for.
	Subject string
	// ClientID is the application holding the token, which is not the user.
	ClientID string
	// Issuer is the authorization server that minted the token.
	Issuer string
	// Scopes the token carries.
	Scopes []string
	// TokenID correlates an audit line with the issuer's own log without
	// writing the token down anywhere.
	TokenID string
	// ExpiresAt is when the token stops being valid.
	ExpiresAt time.Time
}

// Has reports whether the principal carries every scope named.
func (p Principal) Has(scopes ...string) bool { return len(p.Missing(scopes...)) == 0 }

// Missing returns the named scopes the principal does not carry, in the order
// they were asked for, so a refusal can say what was short rather than only
// that something was.
func (p Principal) Missing(scopes ...string) []string { return missingScopes(p.Scopes, scopes) }

// Principal is the part of a verified token a handler is allowed to act on.
func (c Claims) Principal() Principal {
	p := Principal{
		Subject:  c.Subject,
		ClientID: c.ClientID,
		Issuer:   c.Issuer,
		Scopes:   c.Scopes(),
		TokenID:  c.TokenID,
	}
	if c.ExpiresAt != 0 {
		p.ExpiresAt = time.Unix(c.ExpiresAt, 0)
	}
	return p
}

type principalKey struct{}

// withPrincipal hands the handler the principal and takes the token away: what
// the tool serves is a copy of the request with the Authorization header
// removed, so the credential stops at the guard. The request the guard was
// handed is left alone, because it is the caller's, not ours.
func withPrincipal(r *http.Request, p Principal) *http.Request {
	forwarded := r.Clone(context.WithValue(r.Context(), principalKey{}, p))
	forwarded.Header.Del("Authorization")
	return forwarded
}

// PrincipalFrom returns the verified principal for this request. The false
// return is meaningful: it means the handler is running outside the guard,
// which is a wiring mistake rather than an anonymous user.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok
}
