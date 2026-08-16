package mcpaudience

import "context"

type claimsKey struct{}

func withClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ClaimsFrom returns the verified claims for this request. The false return is
// meaningful: it means the handler is running outside the guard, which is a
// wiring mistake rather than an anonymous user.
func ClaimsFrom(ctx context.Context) (Claims, bool) {
	claims, ok := ctx.Value(claimsKey{}).(Claims)
	return claims, ok
}
