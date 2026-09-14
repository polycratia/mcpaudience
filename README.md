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
WWW-Authenticate: Bearer error="insufficient_scope", scope="files:delete", error_description="token does not carry the required scope: tool \"/tools/delete\" needs files:delete; the token carries files:read"
body: token does not carry the required scope: tool "/tools/delete" needs files:delete; the token carries files:read
```

## Use

```go
guard := &mcpaudience.Guard{
	Metadata: mcpaudience.NewMetadata("https://mcp.example.com", "https://auth.example.com").
		WithScopes("files:read", "files:delete"),
	Verifier: &mcpaudience.JWTVerifier{
		Resource: "https://mcp.example.com",
		Issuers:  []string{"https://auth.example.com"},
		Keys:     publicKeysByKeyID,
	},
}

tools := http.NewServeMux()
tools.Handle("/tools/list", listFiles)
tools.Handle("/tools/delete", mcpaudience.Require(deleteFile, "files:delete"))

mux := http.NewServeMux()
guard.Metadata.Mount(mux) // /.well-known/oauth-protected-resource
mux.Handle("/", guard.Handler(tools))
```

Inside a tool, `mcpaudience.ClaimsFrom(r.Context())` gives the verified claims.

## Discovery

`Mount` puts the document at the URL the `401` advertises, and RFC 9728 §3.1 is
fussy about which one that is: the well-known segment goes between the origin
and the resource's path, not after it. A server whose resource identifier is
`https://mcp.example.com/mcp` publishes at
`https://mcp.example.com/.well-known/oauth-protected-resource/mcp` —
`guard.Metadata.URL()` returns that value, and it is the same string the
challenge carries.

`scopes_supported` is a hint for the client's token request. It decides nothing:
what a token may do is settled on the request, against the scopes it actually
carries. A document that would not survive `Validate` is never published — the
handler answers `500` instead, because sending a client to an issuer this server
will not accept tokens from is worse than serving nothing at all.

## Per-tool scopes, and denials that say what is missing

One token, many tools, only some of them dangerous. `Require` puts a tool behind
its own scopes on top of whatever the `Guard` already demanded, and the refusal
is the part worth reading:

```
WWW-Authenticate: Bearer error="insufficient_scope", scope="files:delete",
  error_description="token does not carry the required scope: tool "/tools/delete" needs files:delete; the token carries files:read"
```

A bare `403` tells a caller it lost without telling it what it was short of, and
the next move is to guess: wrong token, wrong tool, wrong user, or a server bug.
So the denial names the tool, names **only** the scopes the token was actually
missing rather than the whole list the route asks for — otherwise callers go
looking for scopes they already hold — and repeats what the token does carry, so
the difference is visible without a debugger. The `scope` parameter is RFC 6750's
own field for the requirement, which makes it something a client reads rather
than parses out of prose.

The tool names itself by its request path. `RequireTool("files/delete", …)` sets
the name explicitly, for servers whose routes are not what clients call their
tools. And `Require` with no scopes answers `500`, like mounting it outside the
`Guard` does: a tool that requires nothing is not guarded, and it reads at the
call site as though it were.

## What it is not

**Not an authorization server.** It issues no tokens, runs no consent screen and
stores no clients. That belongs to an identity provider, and standing one up
inside an MCP server is how "a week of work" becomes a month of work that has
nothing to do with the tools you meant to expose.

**Not a token-format library.** It verifies RS256 and ES256 JWTs against public
keys you already hold. Fetching and rotating a JWKS is not implemented yet, and
is listed below rather than implied.

## Four refusals worth reading

**The audience.** The reason this package has that name, and the one check with
no configuration behind it: no field disables it, and no value of one skips it.
A verifier with no resource identifier does not fall through to accepting
anything — it refuses every token, and the guard answers `500`, because a server
that cannot name itself cannot tell a token meant for it from one that is not.
The same `500` answers a guard whose metadata advertises one resource while its
verifier binds another, rather than sending clients to fetch a token this server
has already decided to reject. Comparison is on the canonical form of both
sides, so `HTTPS://MCP.Example.com:443` and `https://mcp.example.com` are one
server; a different host, port or path is a different one.

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
it the same scopes again — unless it asks for more, which is why the `403` says
which scope, for which tool.

## Status

Early. It covers the resource-server side and says where it stops.

| | |
|---|---|
| Implemented | RFC 9728 metadata document and endpoint, mandatory audience binding, RS256/ES256 verification, expiry with clock skew, issuer allow-list, per-tool scopes with named denials, `WWW-Authenticate` challenges |
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

MIT, by [polycratia](https://polycratia.com) — <hey@polycratia.com>.
