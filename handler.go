package jaws

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

// Handler handles JWT request extraction and validation.
type Handler struct {
	Secret        jwt.Keyfunc
	Signer        SignerFunc
	SigningMethod jwt.SigningMethod
	ErrorResponse http.HandlerFunc

	next http.Handler
}

// ServeHTTP handler implements the http.Handler interface for Handler. It
// extracts the token and processes the requests to another handler, if needed.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(signerToContext(r.Context(), h.Signer))

	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, h.Secret)
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

// Validate catches invalid Handler structs early in your program run. It will
// panic if Handler.SigningMethod, Handler.Secret or h.Signer are nil.
func Validate(h Handler) (Handler, error) {
	if h.SigningMethod == nil || h.Secret == nil || h.Signer == nil {
		return h, fmt.Errorf("no zero values allowed in %v", h)
	}

	if h.ErrorResponse == nil {
		h.ErrorResponse = defaultErrorResponse
	}

	return h, nil
}

// New creates a middleware that decodes JWT tokens and puts them into the
// http.Request context for further use.
//
// The middleware is created from Handler which configuration is validated
// beforehand.
//
// Put this before any other JWT dependent authentication or authorization
// middlewares in your stack.
func New(h Handler) func(http.Handler) http.Handler {
	handler, err := Validate(h)
	if err != nil {
		panic(err)
	}

	return func(next http.Handler) http.Handler {
		handler.next = next
		return handler
	}
}

func defaultErrorResponse(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, "Unauthorized")
}
