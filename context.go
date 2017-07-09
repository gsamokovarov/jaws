package jaws

import (
	"context"

	"github.com/dgrijalva/jwt-go"
)

var (
	tokenKey  = &contextKey{"jaws.token"}
	signerKey = &contextKey{"jaws.signer"}
)

func tokenFromContext(ctx context.Context) (*jwt.Token, error) {
	token, ok := ctx.Value(tokenKey).(*jwt.Token)
	if !ok {
		return nil, &contextError{tokenKey}
	}

	return token, nil
}

func tokenToContext(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

func signerFromContext(ctx context.Context) (Signer, error) {
	signer, ok := ctx.Value(signerKey).(Signer)
	if !ok {
		return nil, &contextError{signerKey}
	}

	return signer, nil
}

func signerToContext(ctx context.Context, signer Signer) context.Context {
	return context.WithValue(ctx, signerKey, signer)
}

type contextKey struct{ name string }

func (c *contextKey) String() string { return c.name }

type contextError struct{ key *contextKey }

func (e *contextError) Error() string { return "missing context key: " + e.key.String() }
