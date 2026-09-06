package mcpaudience

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Guard protects an MCP server's HTTP endpoint.
type Guard struct {
	// Metadata describes this resource. Its Resource field is what tokens are
	// bound to, and the 401 points clients at it.
	Metadata Metadata
	// Verifier turns a token into claims.
	Verifier Verifier
	// RequiredScopes must all be present on any accepted token. Per-tool
	// requirements go through Require instead.
	RequiredScopes []string
}

// Handler wraps next so that only requests with a token for this resource
// reach it.
func (g *Guard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.Verifier == nil {
			http.Error(w, "mcpaudience: no verifier configured", http.StatusInternalServerError)
			return
		}
		token, err := BearerToken(r)
		if err != nil {
			g.challenge(w, err)
			return
		}
		claims, err := g.Verifier.Verify(r.Context(), token)
		if err != nil {
			g.challenge(w, err)
			return
		}
		if len(g.RequiredScopes) > 0 && !claims.HasScope(g.RequiredScopes...) {
			g.challenge(w, fmt.Errorf("%w: %s", ErrMissingScope, strings.Join(g.RequiredScopes, " ")))
			return
		}
		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
	})
}

// Require guards one tool or route behind its own scopes, on top of whatever
// the Guard already demanded.
//
// This is the shape MCP servers actually need: one token, many tools, and only
// some of them dangerous. A single scope for the whole server means the token
// that lists files can also delete them.
func Require(next http.Handler, scopes ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFrom(r.Context())
		if !ok {
			// Reaching here means Require was mounted outside the Guard, which
			// would leave the tool unprotected.
			http.Error(w, "mcpaudience: Require must be mounted inside Guard.Handler", http.StatusInternalServerError)
			return
		}
		if !claims.HasScope(scopes...) {
			writeChallenge(w, "", fmt.Errorf("%w: %s", ErrMissingScope, strings.Join(scopes, " ")))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// BearerToken pulls the token out of the Authorization header, and only from
// there. A token in a query string ends up in access logs, proxies and browser
// history.
func BearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if strings.TrimSpace(header) == "" {
		return "", ErrNoToken
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") || strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("%w: expected \"Authorization: Bearer <token>\"", ErrMalformedToken)
	}
	return strings.TrimSpace(token), nil
}

func (g *Guard) challenge(w http.ResponseWriter, err error) {
	writeChallenge(w, g.Metadata.URL(), err)
}

// writeChallenge answers 401 with the WWW-Authenticate header that tells a
// client where to get a token — the discovery step RFC 9728 adds, and the
// reason a client does not have to be configured with an issuer in advance.
func writeChallenge(w http.ResponseWriter, metadataURL string, err error) {
	code := http.StatusUnauthorized
	parts := []string{`Bearer error="invalid_token"`}

	switch {
	case errors.Is(err, ErrNoToken):
		parts = []string{"Bearer"}
	case errors.Is(err, ErrMissingScope):
		// RFC 6750: not being allowed is 403, not 401. Answering 401 would send
		// a client off to fetch another token that would have the same scopes.
		code = http.StatusForbidden
		parts = []string{`Bearer error="insufficient_scope"`}
	}
	parts = append(parts, fmt.Sprintf("error_description=%q", err.Error()))
	if metadataURL != "" {
		parts = append(parts, fmt.Sprintf("resource_metadata=%q", metadataURL))
	}

	w.Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
	http.Error(w, err.Error(), code)
}
