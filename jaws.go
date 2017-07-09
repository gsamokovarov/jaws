package jaws

import (
	"context"
	"errors"

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

// Claims extracts claims from a JWT token in a request.
func Claims(ctx context.Context) (jwt.MapClaims, error) {
	token, err := Token(ctx)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("cannot convert claims")
	}

	return claims, nil
}
