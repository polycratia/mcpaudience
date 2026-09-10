package mcpaudience

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// There is no configuration that turns the check off, and an unset resource is
// not a back door into one: it refuses every token instead of accepting any.
func TestAudienceBindingHasNoOffSwitch(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	v.Resource = ""

	_, err := v.Verify(context.Background(), s.sign(t, "RS256", "rsa-1", goodClaims()))
	if !errors.Is(err, ErrNoResource) {
		t.Fatalf("err = %v, want ErrNoResource", err)
	}
}

// A server that cannot name itself is broken, not unauthenticated. Answering
// 401 would blame the client for a mistake only the server can fix.
func TestAServerWithNoResourceIdentifierFailsLoudly(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	v.Resource = ""

	response := call(guard(v), okHandler(), "Bearer "+s.sign(t, "RS256", "rsa-1", goodClaims()))
	if response.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 rather than a 401 that hides the misconfiguration", response.Code)
	}
}

// Advertising one resource and checking another sends clients to fetch a token
// this server has already decided it will reject.
func TestAdvertisingOneResourceAndBindingAnotherIsRefused(t *testing.T) {
	s := newSigner(t)
	v := verifier(s)
	v.Resource = "https://other.example.com"

	response := call(guard(v), okHandler(), "Bearer "+s.sign(t, "RS256", "rsa-1", goodClaims()))
	if response.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when the metadata and the verifier disagree", response.Code)
	}
}

func TestATokenWithNoAudienceAtAllIsRefused(t *testing.T) {
	s := newSigner(t)
	claims := goodClaims()
	delete(claims, "aud")

	_, err := verifier(s).Verify(context.Background(), s.sign(t, "RS256", "rsa-1", claims))
	if !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("err = %v, want ErrWrongAudience", err)
	}
}

// The comparison forgives what the URI syntax says means nothing and forgives
// nothing else. A neighbour is not this server.
func TestAudienceComparisonForgivesOnlyWhatCannotChangeTheServer(t *testing.T) {
	cases := map[string]struct {
		audience string
		matches  bool
	}{
		"exact":               {resource, true},
		"trailing slash":      {resource + "/", true},
		"uppercase host":      {"https://MCP.Example.com", true},
		"explicit https port": {"https://mcp.example.com:443", true},
		"another host":        {"https://mcp.example.org", false},
		"suffix lookalike":    {"https://mcp.example.com.evil.example", false},
		"another port":        {"https://mcp.example.com:8443", false},
		"a path below":        {resource + "/mcp", false},
		"a prefix of ours":    {"https://mcp.example", false},
		"empty":               {"", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := (Audience{c.audience}).Contains(resource); got != c.matches {
				t.Errorf("Audience{%q}.Contains(%q) = %v, want %v", c.audience, resource, got, c.matches)
			}
		})
	}
}
