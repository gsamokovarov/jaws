package jaws

import (
	"context"

	"github.com/dgrijalva/jwt-go"
)

// Sign generates a JWT string token from with the secrets configured for the request.
func Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	signer, err := signerFromContext(ctx)
	if err != nil {
		return "", err
	}

	return signer.Sign(claims)
}

// Token returns the JWT token for the request.
func Token(ctx context.Context) (*jwt.Token, error) {
	return tokenFromContext(ctx)
}
