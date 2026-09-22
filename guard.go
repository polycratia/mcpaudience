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
// reach it, and so that what reaches it is the principal rather than the token.
func (g *Guard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.Verifier == nil {
			http.Error(w, "mcpaudience: no verifier configured", http.StatusInternalServerError)
			return
		}
		if err := g.checkBinding(); err != nil {
			http.Error(w, "mcpaudience: "+err.Error(), http.StatusInternalServerError)
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
		principal := claims.Principal()
		if missing := principal.Missing(g.RequiredScopes...); len(missing) > 0 {
			g.challenge(w, &ScopeError{
				Required: g.RequiredScopes,
				Missing:  missing,
				Granted:  principal.Scopes,
			})
			return
		}
		next.ServeHTTP(w, withPrincipal(r, principal))
	})
}

// checkBinding refuses to serve when the resource the challenge advertises is
// not the one tokens are checked against. A client that follows the 401 would
// come back with a token for the advertised resource, this server would reject
// it as the wrong audience, and the loop would look like a client bug.
func (g *Guard) checkBinding() error {
	binder, ok := g.Verifier.(ResourceBinder)
	if !ok {
		return nil
	}
	bound := binder.BoundResource()
	if strings.TrimSpace(bound) == "" {
		return ErrNoResource
	}
	if advertised := g.Metadata.Resource; advertised != "" && !sameResource(advertised, bound) {
		return fmt.Errorf("the metadata advertises %q but tokens are bound to %q", advertised, bound)
	}
	return nil
}

// Require guards one tool or route behind its own scopes, on top of whatever
// the Guard already demanded. The denial names the tool by its request path;
// RequireTool names it explicitly.
//
// This is the shape MCP servers actually need: one token, many tools, and only
// some of them dangerous. A single scope for the whole server means the token
// that lists files can also delete them.
func Require(next http.Handler, scopes ...string) http.Handler {
	return RequireTool("", next, scopes...)
}

// RequireTool is Require for a tool whose route is not the name its callers
// know it by. The name ends up in the refusal, so it should be the one a client
// can look up in its own tool list.
func RequireTool(name string, next http.Handler, scopes ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(scopes) == 0 {
			// A tool that requires nothing is not guarded, and reads at the call
			// site as though it were.
			http.Error(w, "mcpaudience: Require needs at least one scope", http.StatusInternalServerError)
			return
		}
		principal, ok := PrincipalFrom(r.Context())
		if !ok {
			// Reaching here means Require was mounted outside the Guard, which
			// would leave the tool unprotected.
			http.Error(w, "mcpaudience: Require must be mounted inside Guard.Handler", http.StatusInternalServerError)
			return
		}
		tool := name
		if tool == "" {
			tool = r.URL.Path
		}
		if missing := principal.Missing(scopes...); len(missing) > 0 {
			writeChallenge(w, "", &ScopeError{
				Tool:     tool,
				Required: scopes,
				Missing:  missing,
				Granted:  principal.Scopes,
			})
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
	if errors.Is(err, ErrNoResource) {
		// The server cannot name itself, so it cannot tell a token meant for it
		// from one that is not. That is this server's fault, not the client's.
		http.Error(w, "mcpaudience: "+err.Error(), http.StatusInternalServerError)
		return
	}

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
		var scopeErr *ScopeError
		if errors.As(err, &scopeErr) && len(scopeErr.Required) > 0 {
			// RFC 6750 §3.1 has a field for this, so the requirement is one the
			// client can read rather than one it has to parse out of prose.
			parts = append(parts, fmt.Sprintf("scope=%q", strings.Join(scopeErr.Required, " ")))
		}
	}
	parts = append(parts, fmt.Sprintf("error_description=%q", err.Error()))
	if metadataURL != "" {
		parts = append(parts, fmt.Sprintf("resource_metadata=%q", metadataURL))
	}

	w.Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
	http.Error(w, err.Error(), code)
}
