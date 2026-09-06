// Package mcpaudience is the resource-server half of MCP authorization: the
// part an MCP server has to get right so that a token issued for somewhere else
// cannot be spent on it.
//
// The name is the point. An MCP server is an OAuth 2.1 protected resource, and
// the rule that keeps it from becoming a confused deputy is audience binding:
// a token is accepted only if it was issued *for this server*. A validator that
// checks the signature and the expiry and skips the audience will happily
// accept a valid token minted for an unrelated service, and hand that service's
// user everything this one can do.
//
// What this package is not: an authorization server. It does not issue tokens,
// run consent screens or store clients. Those belong to an identity provider,
// and standing one up inside an MCP server is how the "week of work" everyone
// complains about turns into a month.
package mcpaudience

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Metadata is the protected resource metadata document of RFC 9728, which is
// how a client discovers where to get a token for this server.
type Metadata struct {
	// Resource is the canonical URI of this MCP server. It is the value that
	// must appear in a token's audience, so it is the one field that has to be
	// exactly right.
	Resource string `json:"resource"`
	// AuthorizationServers lists issuers a client may use.
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	BearerMethods        []string `json:"bearer_methods_supported,omitempty"`
	ResourceDocs         string   `json:"resource_documentation,omitempty"`
}

// MetadataPath is the well-known segment the document is served under, per
// RFC 9728. For a resource with a path of its own the document sits below it;
// WellKnownPath works that out.
const MetadataPath = "/.well-known/oauth-protected-resource"

// NewMetadata builds a document with the defaults an MCP server wants: the
// token in the Authorization header, and nowhere else. Accepting a token from a
// query string would put it in every access log and browser history between
// here and the client.
func NewMetadata(resource string, authorizationServers ...string) Metadata {
	return Metadata{
		Resource:             resource,
		AuthorizationServers: authorizationServers,
		BearerMethods:        []string{"header"},
	}
}

// WithScopes advertises the scopes a client may ask its authorization server
// for. The list is a hint for discovery, never a decision: what a token is
// allowed to do is settled here, on the request, against the scopes it carries.
func (m Metadata) WithScopes(scopes ...string) Metadata {
	m.ScopesSupported = scopes
	return m
}

// Validate refuses a document a client could not act on.
func (m Metadata) Validate() error {
	if err := canonicalURI(m.Resource); err != nil {
		return fmt.Errorf("resource: %w", err)
	}
	if len(m.AuthorizationServers) == 0 {
		return fmt.Errorf("authorization_servers: at least one issuer is required")
	}
	for _, issuer := range m.AuthorizationServers {
		if err := canonicalURI(issuer); err != nil {
			return fmt.Errorf("authorization_servers: %w", err)
		}
	}
	for _, method := range m.BearerMethods {
		// The other two methods RFC 6750 allows put the token in a query
		// string or a form body. Both leak it into logs.
		if method != "header" {
			return fmt.Errorf("bearer_methods_supported: %q puts the token where it will be logged", method)
		}
	}
	return nil
}

// WellKnownPath is the path the document has to be served at, per RFC 9728
// §3.1: the well-known segment goes between the origin and the resource's path,
// not after it. A server at https://mcp.example.com/mcp publishes at
// /.well-known/oauth-protected-resource/mcp, and appending instead would leave
// clients fetching a URL nothing serves.
func (m Metadata) WellKnownPath() string {
	parsed, err := url.Parse(m.Resource)
	if err != nil {
		return MetadataPath
	}
	return MetadataPath + strings.TrimSuffix(parsed.Path, "/")
}

// URL is the absolute location of the document: the value a 401 hands back in
// resource_metadata, and the one clients will actually fetch.
func (m Metadata) URL() string {
	if strings.TrimSpace(m.Resource) == "" {
		return ""
	}
	parsed, err := url.Parse(m.Resource)
	if err != nil {
		return ""
	}
	parsed.Path = MetadataPath + strings.TrimSuffix(parsed.Path, "/")
	return parsed.String()
}

// Mount registers the document on mux at the path the challenge advertises, so
// that discovery cannot drift from what the 401 promised.
func (m Metadata) Mount(mux *http.ServeMux) {
	mux.Handle(m.WellKnownPath(), m.Handler())
}

// Handler serves the metadata document. A document that would not survive
// Validate is answered with a 500 instead: publishing one is worse than
// publishing nothing, because it sends clients to fetch tokens this server has
// already decided it will not accept.
func (m Metadata) Handler() http.Handler {
	if err := m.Validate(); err != nil {
		message := "mcpaudience: metadata document is invalid: " + err.Error()
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, message, http.StatusInternalServerError)
		})
	}
	body, _ := json.Marshal(m)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("content-type", "application/json")
		// Discovery documents are read on every cold start of every client.
		w.Header().Set("cache-control", "public, max-age=3600")
		w.Write(body)
	})
}

// canonicalURI enforces what an audience value has to be for comparison to mean
// anything: absolute, https, no fragment, no query.
func canonicalURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URI: %w", raw, err)
	}
	switch {
	case !parsed.IsAbs():
		return fmt.Errorf("%q must be absolute", raw)
	case parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1":
		return fmt.Errorf("%q must use https outside localhost", raw)
	case parsed.Fragment != "":
		return fmt.Errorf("%q must not carry a fragment", raw)
	case parsed.RawQuery != "":
		return fmt.Errorf("%q must not carry a query string", raw)
	}
	return nil
}
