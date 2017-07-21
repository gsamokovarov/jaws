package jaws

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

// Handler handles JWT request extraction and validation. It also servers as a
// configuration struct to the New function.
type Handler struct {
	Secret        []byte
	SecretFunc    jwt.Keyfunc
	SignerFunc    SignerFunc
	SigningMethod jwt.SigningMethod
	ErrorResponse http.HandlerFunc

	next http.Handler
}

// ServeHTTP handler implements the http.Handler interface for Handler. It
// extracts the token and processes the requests to another handler, if needed.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(signerToContext(r.Context(), h.SignerFunc))

	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, h.SecretFunc)
	if err == request.ErrNoTokenInRequest {
		h.next.ServeHTTP(w, r)
		return
	}

	if err != nil || h.SigningMethod.Alg() != token.Header["alg"] || !token.Valid {
		h.ErrorResponse(w, r)
		return
	}

	h.next.ServeHTTP(w, r.WithContext(tokenToContext(r.Context(), token)))
}

// New creates a middleware that decodes JWT tokens and puts them into the
// http.Request context for further use.
//
// The middleware is created from Handler which configuration. There are two
// strategies: simplified or fully configured Handler.
//
// The simplified strategy requires the Secret and SigningMethod fields present:
//
//	New(Handler{
//		Secret: GetSecretFromEnv(),
//		SigningMethod: jwt.SigningMethodHS256
//	})
//
// The SecretFunc and SignerFunc fields get populated with default values,
// based on the given Secret and SigningMethod above.
//
// The full strategy requires SecretFunc, SignerFunc and SigningMethod present:
//
//	New(jaws.Handler{
//		Secret: func(*jwt.Token) (interface{}, error) {
//			return secret, nil
//		},
//		Signer: func(claims jwt.Claims) (string, error) {
//			return jwt.
//				NewWithClaims(GetSigningMethod(), claims).
//				SignedString(GetSecret())
//		},
//		SigningMethod: GetSigningMethod()
//	})
//
// The ErrorResponse field can get a default value for either of the
// configuration strategies.
//
// Put this before any other JWT dependent authentication or authorization
// middlewares in your stack.
func New(h Handler) func(http.Handler) http.Handler {
	handler, err := validate(h)
	if err != nil {
		panic(err)
	}

	return func(next http.Handler) http.Handler {
		handler.next = next
		return handler
	}
}

func validate(h Handler) (Handler, error) {
	if h.Secret != nil && h.SecretFunc == nil {
		h.SecretFunc = defaultSecretFunc(h.Secret)
	}
	if h.Secret != nil && h.SignerFunc == nil {
		h.SignerFunc = defaultSignerFunc(h.SigningMethod, h.Secret)
	}
	if h.ErrorResponse == nil {
		h.ErrorResponse = defaultErrorResponse
	}

	// Check the values after some of them got defaulted.
	if h.SigningMethod == nil || h.SecretFunc == nil || h.SignerFunc == nil {
		return h, fmt.Errorf("no zero values allowed in %v", h)
	}

	return h, nil
}

func defaultErrorResponse(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, "Unauthorized")
}

func defaultSecretFunc(secret []byte) jwt.Keyfunc {
	return func(*jwt.Token) (interface{}, error) {
		return secret, nil
	}
}

func defaultSignerFunc(signingMethod jwt.SigningMethod, secret []byte) SignerFunc {
	return func(claims jwt.Claims) (string, error) {
		return jwt.
			NewWithClaims(signingMethod, claims).
			SignedString(secret)

	}
}
