package mcpaudience

import (
	"context"
	"encoding/json"
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
	r := httptest.NewRequest(http.MethodPost, resource+"/mcp", nil)
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
	if !strings.Contains(response.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("challenge = %q, want insufficient_scope", response.Header().Get("WWW-Authenticate"))
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

func TestMetadataDocument(t *testing.T) {
	metadata := NewMetadata(resource, "https://auth.example.com")
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	metadata.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, MetadataPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var served Metadata
	if err := json.Unmarshal(w.Body.Bytes(), &served); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	if served.Resource != resource || len(served.AuthorizationServers) != 1 {
		t.Errorf("document = %+v", served)
	}
	if len(served.BearerMethods) != 1 || served.BearerMethods[0] != "header" {
		t.Errorf("bearer methods = %v, want the header only", served.BearerMethods)
	}
}

func TestMetadataRefusesWhatCannotBeCompared(t *testing.T) {
	cases := map[string]Metadata{
		"no resource":    {AuthorizationServers: []string{"https://auth.example.com"}},
		"relative":       {Resource: "/mcp", AuthorizationServers: []string{"https://auth.example.com"}},
		"plain http":     {Resource: "http://mcp.example.com", AuthorizationServers: []string{"https://auth.example.com"}},
		"with fragment":  {Resource: resource + "#tools", AuthorizationServers: []string{"https://auth.example.com"}},
		"with query":     {Resource: resource + "?v=1", AuthorizationServers: []string{"https://auth.example.com"}},
		"no issuers":     {Resource: resource},
		"token in query": {Resource: resource, AuthorizationServers: []string{"https://auth.example.com"}, BearerMethods: []string{"query"}},
	}
	for name, metadata := range cases {
		t.Run(name, func(t *testing.T) {
			if err := metadata.Validate(); err == nil {
				t.Error("accepted")
			}
		})
	}

	// localhost over plain http is how everyone develops.
	local := NewMetadata("http://localhost:8080", "http://localhost:9000")
	if err := local.Validate(); err != nil {
		t.Errorf("localhost was refused: %v", err)
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
