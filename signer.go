package jaws

import (
	"github.com/dgrijalva/jwt-go"
)

// Signer can sign claims into a JWT token string.
type Signer interface {
	Sign(jwt.Claims) (string, error)
}

// SignerFunc lets a func(jwt.Claims) (string, error) be used as a Signer.
type SignerFunc func(jwt.Claims) (string, error)

// Sign implements the Signer protocol.
func (s SignerFunc) Sign(claims jwt.Claims) (string, error) {
	return s(claims)
}
