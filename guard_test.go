package mcpaudience

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubVerifier stands in for a real token check so the guard's own behaviour is
// what is under test.
type stubVerifier struct {
	claims Claims
	err    error
}

func (s stubVerifier) Verify(context.Context, string) (Claims, error) { return s.claims, s.err }

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFrom(r.Context())
		w.Write([]byte("served for " + claims.Subject))
	})
}

func guard(v Verifier, scopes ...string) *Guard {
	return &Guard{
		Metadata:       NewMetadata(resource, "https://auth.example.com"),
		Verifier:       v,
		RequiredScopes: scopes,
	}
}

func call(g *Guard, handler http.Handler, authorization string) *httptest.ResponseRecorder {
	return callPath(g, handler, "/mcp", authorization)
}

func callPath(g *Guard, handler http.Handler, path, authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, resource+path, nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	g.Handler(handler).ServeHTTP(w, r)
	return w
}

// A 401 that does not say where to get a token forces every client to be
// configured by hand. RFC 9728 exists to avoid exactly that.
func TestUnauthenticatedRequestIsPointedAtTheMetadata(t *testing.T) {
	response := call(guard(stubVerifier{err: ErrNoToken}), okHandler(), "")

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	challenge := response.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="`+resource+MetadataPath+`"`) {
		t.Errorf("challenge does not point at the metadata: %q", challenge)
	}
}

func TestAValidTokenReachesTheHandler(t *testing.T) {
	v := stubVerifier{claims: Claims{Subject: "user-1", Scope: "mcp:read", Active: true}}
	response := call(guard(v), okHandler(), "Bearer abc")

	if response.Code != http.StatusOK || response.Body.String() != "served for user-1" {
		t.Errorf("status = %d, body = %q", response.Code, response.Body)
	}
}

// Missing scope is 403, not 401: sending a client to fetch another token would
// only get it the same scopes again.
func TestMissingScopeIsForbiddenRatherThanUnauthorized(t *testing.T) {
	v := stubVerifier{claims: Claims{Subject: "user-1", Scope: "mcp:read", Active: true}}
	response := call(guard(v, "mcp:write"), okHandler(), "Bearer abc")

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	challenge := response.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "insufficient_scope") {
		t.Errorf("challenge = %q, want insufficient_scope", challenge)
	}
	if !strings.Contains(challenge, "mcp:write") {
		t.Errorf("challenge = %q, want it to name the scope the server demanded", challenge)
	}
}

// One token, many tools, only some of them dangerous.
func TestPerToolScopes(t *testing.T) {
	v := stubVerifier{claims: Claims{Subject: "user-1", Scope: "files:read", Active: true}}
	g := guard(v)

	readable := call(g, Require(okHandler(), "files:read"), "Bearer abc")
	if readable.Code != http.StatusOK {
		t.Errorf("read tool: status = %d, want 200", readable.Code)
	}

	dangerous := call(g, Require(okHandler(), "files:delete"), "Bearer abc")
	if dangerous.Code != http.StatusForbidden {
		t.Errorf("delete tool: status = %d, want 403 for a token that only reads", dangerous.Code)
	}
}

// A bare 403 leaves the caller to guess between a wrong token, a wrong tool and
// a server bug. The denial names both the tool and the scope it wanted.
func TestADenialNamesTheToolAndTheMissingScope(t *testing.T) {
	v := stubVerifier{claims: Claims{Subject: "user-1", Scope: "files:read", Active: true}}
	response := callPath(guard(v), Require(okHandler(), "files:delete"), "/tools/delete", "Bearer abc")

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	challenge := response.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `scope="files:delete"`) {
		t.Errorf("challenge = %q, want the RFC 6750 scope parameter", challenge)
	}
	for _, want := range []string{"/tools/delete", "files:delete", "files:read"} {
		if !strings.Contains(challenge, want) {
			t.Errorf("challenge = %q, want it to mention %q", challenge, want)
		}
	}
	if !strings.Contains(response.Body.String(), "/tools/delete") {
		t.Errorf("body = %q, want the tool named there too", response.Body)
	}
}

// Reporting the whole requirement as if it were the shortfall sends people
// looking for scopes they already hold.
func TestADenialNamesOnlyTheScopesTheTokenLacks(t *testing.T) {
	claims := Claims{Scope: "files:read", Active: true}

	missing := claims.MissingScopes("files:read", "files:delete")
	if len(missing) != 1 || missing[0] != "files:delete" {
		t.Fatalf("missing = %v, want only files:delete", missing)
	}

	denial := &ScopeError{Tool: "files/delete", Required: []string{"files:read", "files:delete"}, Missing: missing, Granted: claims.Scopes()}
	if got := denial.Error(); !strings.Contains(got, `needs files:delete;`) {
		t.Errorf("denial = %q, want it to name the shortfall rather than the whole requirement", got)
	}
}

func TestADenialSaysSoWhenTheTokenCarriesNoScopesAtAll(t *testing.T) {
	v := stubVerifier{claims: Claims{Subject: "user-1", Active: true}}
	response := callPath(guard(v), Require(okHandler(), "files:delete"), "/tools/delete", "Bearer abc")

	if !strings.Contains(response.Body.String(), "no scopes at all") {
		t.Errorf("body = %q, want it to say the token carries nothing", response.Body)
	}
}

// The route is not always the name a client knows the tool by.
func TestRequireToolNamesTheToolRatherThanTheRoute(t *testing.T) {
	v := stubVerifier{claims: Claims{Subject: "user-1", Scope: "files:read", Active: true}}
	handler := RequireTool("files/delete", okHandler(), "files:delete")
	response := callPath(guard(v), handler, "/rpc", "Bearer abc")

	if !strings.Contains(response.Body.String(), "files/delete") {
		t.Errorf("body = %q, want the declared tool name", response.Body)
	}
}

// A tool that requires nothing reads at the call site as though it were
// guarded, so it refuses to run rather than serving unguarded.
func TestRequireWithNoScopesFailsLoudly(t *testing.T) {
	v := stubVerifier{claims: Claims{Subject: "user-1", Scope: "files:read", Active: true}}
	response := call(guard(v), Require(okHandler()), "Bearer abc")

	if response.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", response.Code)
	}
}

// Mounting Require outside the guard would leave a tool unprotected, so it
// fails loudly instead of running.
func TestRequireOutsideTheGuardFailsLoudly(t *testing.T) {
	w := httptest.NewRecorder()
	Require(okHandler(), "files:read").ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestBearerTokenExtraction(t *testing.T) {
	cases := map[string]struct {
		header string
		want   string
		fails  bool
	}{
		"standard":     {header: "Bearer abc", want: "abc"},
		"lowercase":    {header: "bearer abc", want: "abc"},
		"extra spaces": {header: "Bearer   abc  ", want: "abc"},
		"missing":      {header: "", fails: true},
		"wrong scheme": {header: "Basic abc", fails: true},
		"no token":     {header: "Bearer ", fails: true},
		"scheme only":  {header: "Bearer", fails: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			got, err := BearerToken(r)
			if c.fails {
				if err == nil {
					t.Errorf("accepted %q", c.header)
				}
				return
			}
			if err != nil || got != c.want {
				t.Errorf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

// RFC 9728 puts the well-known segment between the origin and the path. For a
// resource at /mcp, appending would point clients at
// /mcp/.well-known/oauth-protected-resource, a URL nothing serves.
func TestMetadataPointerForAPathBearingResource(t *testing.T) {
	g := &Guard{
		Metadata: NewMetadata("https://mcp.example.com/mcp", "https://auth.example.com"),
		Verifier: stubVerifier{err: ErrNoToken},
	}
	r := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", nil)
	w := httptest.NewRecorder()
	g.Handler(okHandler()).ServeHTTP(w, r)

	challenge := w.Header().Get("WWW-Authenticate")
	want := `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`
	if !strings.Contains(challenge, want) {
		t.Errorf("challenge = %q, want it to carry %s", challenge, want)
	}
}

func TestMisconfiguredGuardFailsLoudly(t *testing.T) {
	g := &Guard{Metadata: NewMetadata(resource, "https://auth.example.com")}
	if response := call(g, okHandler(), "Bearer abc"); response.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when no verifier is configured", response.Code)
	}
}
