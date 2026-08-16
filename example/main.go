// Command example runs a guarded MCP endpoint and walks four requests through
// it: no token, a token minted for another service, a valid token, and a valid
// token reaching for a tool it was not granted.
//
//	go run ./example
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/polycratia/mcpaudience"
)

const (
	resource = "https://mcp.example.com"
	issuer   = "https://auth.example.com"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	guard := &mcpaudience.Guard{
		Metadata: mcpaudience.NewMetadata(resource, issuer),
		Verifier: &mcpaudience.JWTVerifier{
			Resource: resource,
			Issuers:  []string{issuer},
			Keys:     map[string]crypto.PublicKey{"key-1": &key.PublicKey},
		},
	}

	tools := http.NewServeMux()
	tools.Handle("/tools/list", handler("listed the files"))
	tools.Handle("/tools/delete", mcpaudience.Require(handler("deleted the file"), "files:delete"))

	server := httptest.NewServer(guard.Handler(tools))
	defer server.Close()

	fmt.Println("--- no token ---")
	show(get(server.URL+"/tools/list", ""))

	fmt.Println("\n--- token issued for another service ---")
	show(get(server.URL+"/tools/list", token(key, "https://another-service.example.com", "files:read")))

	fmt.Println("\n--- token issued for this server ---")
	show(get(server.URL+"/tools/list", token(key, resource, "files:read")))

	fmt.Println("\n--- same token, reaching for a tool it was not granted ---")
	show(get(server.URL+"/tools/delete", token(key, resource, "files:read")))
}

func handler(said string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := mcpaudience.ClaimsFrom(r.Context())
		fmt.Fprintf(w, "%s for %s", said, claims.Subject)
	})
}

func token(key *rsa.PrivateKey, audience, scope string) string {
	header := segment(map[string]string{"alg": "RS256", "kid": "key-1", "typ": "JWT"})
	payload := segment(map[string]any{
		"iss":   issuer,
		"sub":   "user-1",
		"aud":   audience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": scope,
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

func get(url, bearer string) *http.Response {
	request, _ := http.NewRequest(http.MethodGet, url, nil)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		panic(err)
	}
	return response
}

func show(response *http.Response) {
	defer response.Body.Close()
	body := make([]byte, 512)
	n, _ := response.Body.Read(body)
	fmt.Printf("status: %d\n", response.StatusCode)
	if challenge := response.Header.Get("WWW-Authenticate"); challenge != "" {
		fmt.Printf("WWW-Authenticate: %s\n", challenge)
	}
	fmt.Printf("body: %s", body[:n])
}
