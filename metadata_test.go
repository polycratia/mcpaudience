package mcpaudience

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", contentType)
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
	if strings.Contains(w.Body.String(), "scopes_supported") {
		t.Errorf("a server that advertises no scopes should omit the key: %s", w.Body)
	}
}

func TestMetadataAdvertisesTheScopesAClientCanAskFor(t *testing.T) {
	metadata := NewMetadata(resource, "https://auth.example.com").WithScopes("files:read", "files:delete")

	w := httptest.NewRecorder()
	metadata.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, MetadataPath, nil))

	var served Metadata
	if err := json.Unmarshal(w.Body.Bytes(), &served); err != nil {
		t.Fatalf("document is not JSON: %v", err)
	}
	if len(served.ScopesSupported) != 2 || served.ScopesSupported[0] != "files:read" {
		t.Errorf("scopes = %v, want the two that were advertised", served.ScopesSupported)
	}
}

// The document has to answer at the URL the 401 named, or discovery buys the
// client nothing.
func TestTheDocumentIsServedWhereTheChallengePointsForAPathBearingResource(t *testing.T) {
	metadata := NewMetadata("https://mcp.example.com/mcp", "https://auth.example.com")

	want := "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
	if got := metadata.URL(); got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}

	mux := http.NewServeMux()
	metadata.Mount(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, metadata.URL(), nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d at the advertised URL, want 200", w.Code)
	}
}

func TestTheDocumentIsReadOnly(t *testing.T) {
	metadata := NewMetadata(resource, "https://auth.example.com")

	posted := httptest.NewRecorder()
	metadata.Handler().ServeHTTP(posted, httptest.NewRequest(http.MethodPost, MetadataPath, nil))
	if posted.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status = %d, want 405", posted.Code)
	}
	if allow := posted.Header().Get("Allow"); allow == "" {
		t.Error("a 405 without an Allow header leaves the client guessing")
	}

	head := httptest.NewRecorder()
	metadata.Handler().ServeHTTP(head, httptest.NewRequest(http.MethodHead, MetadataPath, nil))
	if head.Code != http.StatusOK {
		t.Errorf("HEAD: status = %d, want 200", head.Code)
	}
}

// Publishing a document nobody can act on is worse than publishing none: it
// sends clients off to fetch tokens this server would refuse anyway.
func TestAnUnusableDocumentIsNotPublished(t *testing.T) {
	broken := Metadata{Resource: resource}

	w := httptest.NewRecorder()
	broken.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, MetadataPath, nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 rather than a document with no issuer in it", w.Code)
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
