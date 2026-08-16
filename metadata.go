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

// MetadataPath is where the document is served, per RFC 9728.
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

// Handler serves the metadata document.
func (m Metadata) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := json.Marshal(m)
		if err != nil {
			http.Error(w, "metadata could not be encoded", http.StatusInternalServerError)
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
