package jaws

import (
	"context"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

// Sign generates a JWT string token from with the secrets configured within
// the context. This will usually be the request context. Applications can
// build on-top of this function to say, sign tokens users with
// jwt.StandardClaims.
func Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	signer, err := signerFromContext(ctx)
	if err != nil {
		return "", err
	}

	return signer.Sign(claims)
}

// Token returns a JWT token from a context. This will usually be the request
// context.
func Token(ctx context.Context) (*jwt.Token, error) {
	return tokenFromContext(ctx)
}

// Claims extracts claims from of a JWT token from a context.  This will
// usually be the request context.
func Claims(ctx context.Context) (jwt.MapClaims, error) {
	token, err := Token(ctx)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		claims = jwt.MapClaims{}
	}

	return claims, nil
}

// Mock creates a context suitable for encoding and decoding tokens, from a
// request. Useful in tests.
func Mock(r *http.Request, secret jwt.Keyfunc, signer SignerFunc) (context.Context, error) {
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, secret)
	if err != nil && err != request.ErrNoTokenInRequest {
		return nil, err
	}

	r = r.WithContext(signerToContext(r.Context(), signer))
	r = r.WithContext(tokenToContext(r.Context(), token))

	return r.Context(), nil
}
