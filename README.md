# mcpaudience

The resource-server half of MCP authorization, in one small Go package.

An MCP server is an OAuth 2.1 protected resource. The rule that keeps it from
becoming somebody else's deputy is audience binding: accept a token only if it
was issued **for this server**. A validator that checks the signature and the
expiry and skips the audience will happily accept a valid token minted for an
unrelated service — and hand that service's user everything this one can do.

```console
$ go run ./example
--- no token ---
status: 401
WWW-Authenticate: Bearer, error_description="no bearer token presented", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"

--- token issued for another service ---
status: 401
WWW-Authenticate: Bearer error="invalid_token", error_description="token was not issued for this resource: audience [https://another-service.example.com] does not include \"https://mcp.example.com\"", …

--- token issued for this server ---
status: 200
body: listed the files for user-1

--- same token, reaching for a tool it was not granted ---
status: 403
WWW-Authenticate: Bearer error="insufficient_scope", error_description="token does not carry the required scope: files:delete"
```

## Use

```go
guard := &mcpaudience.Guard{
	Metadata: mcpaudience.NewMetadata("https://mcp.example.com", "https://auth.example.com"),
	Verifier: &mcpaudience.JWTVerifier{
		Resource: "https://mcp.example.com",
		Issuers:  []string{"https://auth.example.com"},
		Keys:     publicKeysByKeyID,
	},
}

tools := http.NewServeMux()
tools.Handle("/tools/list", listFiles)
tools.Handle("/tools/delete", mcpaudience.Require(deleteFile, "files:delete"))

http.Handle("/.well-known/oauth-protected-resource", guard.Metadata.Handler())
http.Handle("/", guard.Handler(tools))
```

Inside a tool, `mcpaudience.ClaimsFrom(r.Context())` gives the verified claims.

## What it is not

**Not an authorization server.** It issues no tokens, runs no consent screen and
stores no clients. That belongs to an identity provider, and standing one up
inside an MCP server is how "a week of work" becomes a month of work that has
nothing to do with the tools you meant to expose.

**Not a token-format library.** It verifies RS256 and ES256 JWTs against public
keys you already hold. Fetching and rotating a JWKS is not implemented yet, and
is listed below rather than implied.

## Four refusals worth reading

**The audience.** The reason this package has that name. Covered above.

**`alg: none` and `alg: HS256`.** `none` means "trust me". An HMAC algorithm
against a set of public keys is the algorithm-confusion attack: the attacker
signs with the public key as the shared secret, and a verifier that dispatches
on the header's `alg` alone accepts it. Both are refused with a message that
names what happened.

**A token with no expiry.** That is not a token, it is a password.

**A token in a query string.** The metadata document advertises the
`Authorization` header and nothing else, and `Validate` refuses to publish
anything else, because a token in a URL ends up in access logs, proxy logs and
browser history.

## Two status codes people get wrong

`401` means "I do not know who you are" and carries `WWW-Authenticate` with
`resource_metadata`, so a client can discover where to get a token instead of
being configured by hand.

`403` means "I know who you are and this is not yours". Missing scope answers
`403`, never `401`: sending a client off to fetch another token would only get
it the same scopes again.

## Status

Early. It covers the resource-server side and says where it stops.

| | |
|---|---|
| Implemented | RFC 9728 metadata document, audience binding, RS256/ES256 verification, expiry with clock skew, issuer allow-list, per-tool scopes, `WWW-Authenticate` challenges |
| Not yet | JWKS fetching and key rotation, RFC 7662 introspection for opaque tokens, resource indicators on the client side, token caching |

The MCP authorization specification is young and has changed more than once. This
targets the resource-server behaviour that has been stable across those
revisions — protected resource metadata and audience binding — rather than
chasing every draft.

Go 1.24 or newer. No dependencies outside the standard library.

## Development

```bash
make test   # go vet + go test ./...
make demo   # the transcript above
```

## License

MIT
