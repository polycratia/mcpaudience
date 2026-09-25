// Command mcpsdk wires the guard into an MCP server that speaks JSON-RPC over
// a single HTTP endpoint, which is the shape a Go MCP SDK hands back from its
// streamable HTTP transport: an http.Handler. Authorization is middleware in
// front of it, and the tools behind it never see a token.
//
//	go run ./example/mcpsdk
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/polycratia/mcpaudience"
)

const (
	resource = "https://mcp.example.com"
	issuer   = "https://auth.example.com"
	endpoint = "/mcp"
)

// tool is one entry of the registry an SDK builds a server from: a name, the
// scopes a caller needs to reach it, and the work.
type tool struct {
	name   string
	scopes []string
	run    func(mcpaudience.Principal) string
}

var catalogue = []tool{
	{
		name:   "files/list",
		scopes: []string{"files:read"},
		run: func(p mcpaudience.Principal) string {
			return "notes.md, receipts.csv — listed for " + p.Subject
		},
	},
	{
		name:   "files/delete",
		scopes: []string{"files:delete"},
		run: func(p mcpaudience.Principal) string {
			return "deleted notes.md for " + p.Subject
		},
	},
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	guard := &mcpaudience.Guard{
		Metadata: mcpaudience.NewMetadata(resource, issuer).
			WithScopes("files:read", "files:delete"),
		Verifier: &mcpaudience.JWTVerifier{
			Resource: resource,
			Issuers:  []string{issuer},
			Keys:     map[string]crypto.PublicKey{"key-1": &key.PublicKey},
		},
		RequiredScopes: []string{"files:read"},
	}

	mux := http.NewServeMux()
	guard.Metadata.Mount(mux)
	mux.Handle(endpoint, guard.Handler(handler(catalogue)))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	readOnly := token(key, resource, "files:read")

	fmt.Println("--- discovery: the document the 401 points at ---")
	show(get(srv.URL + mcpaudience.MetadataPath))

	fmt.Println("\n--- tools/list with no token ---")
	show(post(srv.URL+endpoint, "", "tools/list", nil))

	fmt.Println("\n--- tools/list with a token minted for another service ---")
	show(post(srv.URL+endpoint, token(key, "https://another-service.example.com", "files:read"), "tools/list", nil))

	fmt.Println("\n--- tools/list with a token for this server ---")
	show(post(srv.URL+endpoint, readOnly, "tools/list", nil))

	fmt.Println("\n--- tools/call files/list ---")
	show(post(srv.URL+endpoint, readOnly, "tools/call", map[string]any{"name": "files/list"}))

	fmt.Println("\n--- tools/call files/delete with the same token ---")
	show(post(srv.URL+endpoint, readOnly, "tools/call", map[string]any{"name": "files/delete"}))
}

// handler stands in for what an SDK builds from a registry: one endpoint with
// every tool multiplexed behind a method name. Nothing in it reads a header —
// the guard in front has already turned a token into a principal, or refused
// the request before it got here.
func handler(tools []tool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			write(w, 0, nil, &rpcError{Code: -32700, Message: "parse error: " + err.Error()})
			return
		}

		switch call.Method {
		case "tools/list":
			listed, err := listTools(r.Context(), tools)
			if err != nil {
				write(w, call.ID, nil, &rpcError{Code: -32603, Message: err.Error()})
				return
			}
			write(w, call.ID, map[string]any{"tools": listed}, nil)
		case "tools/call":
			text, err := callTool(r.Context(), tools, call.Params.Name)
			if err != nil {
				// The transport-level answer was already given: this request
				// carried a token for this server, so the refusal belongs to
				// the call rather than to the connection.
				write(w, call.ID, nil, &rpcError{Code: -32001, Message: err.Error()})
				return
			}
			write(w, call.ID, map[string]any{
				"content": []map[string]string{{"type": "text", "text": text}},
			}, nil)
		default:
			write(w, call.ID, nil, &rpcError{Code: -32601, Message: "unknown method " + call.Method})
		}
	})
}

// callTool is the seam this example exists for. An SDK hands a tool handler a
// context and nothing else of the request, and the principal is on it, so the
// scope check lives here — mcpaudience.Require has no route to wrap when every
// tool arrives as a tools/call on the same one.
func callTool(ctx context.Context, tools []tool, name string) (string, error) {
	principal, err := caller(ctx)
	if err != nil {
		return "", err
	}
	for _, t := range tools {
		if t.name != name {
			continue
		}
		if missing := principal.Missing(t.scopes...); len(missing) > 0 {
			return "", &mcpaudience.ScopeError{
				Tool:     t.name,
				Required: t.scopes,
				Missing:  missing,
				Granted:  principal.Scopes,
			}
		}
		return t.run(principal), nil
	}
	return "", fmt.Errorf("no tool named %q", name)
}

// listTools answers with the tools this token can actually call. Listing one it
// will be refused costs the client a turn to find that out.
func listTools(ctx context.Context, tools []tool) ([]map[string]any, error) {
	principal, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	listed := []map[string]any{}
	for _, t := range tools {
		if principal.Has(t.scopes...) {
			listed = append(listed, map[string]any{"name": t.name, "scopes": t.scopes})
		}
	}
	return listed, nil
}

func caller(ctx context.Context) (mcpaudience.Principal, error) {
	principal, ok := mcpaudience.PrincipalFrom(ctx)
	if !ok {
		// Not an anonymous caller: the endpoint is mounted outside the guard,
		// which would leave every tool on it unprotected.
		return principal, errors.New("the mcp endpoint is mounted outside the guard")
	}
	return principal, nil
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func write(w http.ResponseWriter, id int, result any, failure *rpcError) {
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(struct {
		JSONRPC string    `json:"jsonrpc"`
		ID      int       `json:"id"`
		Result  any       `json:"result,omitempty"`
		Error   *rpcError `json:"error,omitempty"`
	}{JSONRPC: "2.0", ID: id, Result: result, Error: failure})
}

func token(key *rsa.PrivateKey, audience, scope string) string {
	header := segment(map[string]string{"alg": "RS256", "kid": "key-1", "typ": "JWT"})
	payload := segment(map[string]any{
		"iss":       issuer,
		"sub":       "user-1",
		"aud":       audience,
		"exp":       time.Now().Add(time.Hour).Unix(),
		"scope":     scope,
		"client_id": "inspector",
	})
	digest := sha256.Sum256([]byte(header + "." + payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func segment(value any) string {
	body, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(body)
}

func post(url, bearer, method string, params map[string]any) *http.Response {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	request, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	request.Header.Set("content-type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(request)
}

func get(url string) *http.Response {
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	return do(request)
}

func do(request *http.Request) *http.Response {
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		panic(err)
	}
	return response
}

func show(response *http.Response) {
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	fmt.Printf("status: %d\n", response.StatusCode)
	if challenge := response.Header.Get("WWW-Authenticate"); challenge != "" {
		fmt.Printf("WWW-Authenticate: %s\n", challenge)
	}
	fmt.Printf("body: %s\n", bytes.TrimSpace(body))
}
