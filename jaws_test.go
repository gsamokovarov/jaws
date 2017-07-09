package jaws

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

var (
	jwtHandler = Handler{
		SigningMethod: jwt.SigningMethodHS256,
		Secret: func(*jwt.Token) (interface{}, error) {
			return []byte("test1234"), nil
		},
		Signer: func(claims jwt.Claims) (string, error) {
			return jwt.
				NewWithClaims(jwt.SigningMethodHS256, claims).
				SignedString([]byte("test1234"))
		},
		ErrorResponse: func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"code": "unauthorized"}`)
		},
	}

	jwtTokenString = generateStringToken(jwtHandler, jwt.MapClaims{"foo": "bar"})
)

func TestValidate_RequiresSigningMethod(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected Validate to require SingingMethod")
		}
	}()

	Validate(Handler{
		Secret: jwtHandler.Secret,
	})
}

func TestValidate_RequiresSigner(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected Validate to require Signer")
		}
	}()

	Validate(Handler{
		Secret:        jwtHandler.Secret,
		SigningMethod: jwtHandler.SigningMethod,
	})
}

func TestValidate_RequiresSecret(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected Validate to require Secret")
		}
	}()

	Validate(Handler{
		SigningMethod: jwtHandler.SigningMethod,
		Signer:        jwtHandler.Signer,
	})
}

func TestValidate_DefaultsErrorResponse(t *testing.T) {
	t.Parallel()

	m := Validate(Handler{
		SigningMethod: jwtHandler.SigningMethod,
		Secret:        jwtHandler.Secret,
		Signer:        jwtHandler.Signer,
	})

	if m.ErrorResponse == nil {
		t.Errorf("Expected Validate to not be nil, got: %v", m)
	}
}

func TestHandler_TokenDecoding(t *testing.T) {
	t.Parallel()

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+jwtTokenString)

	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := Token(r.Context())
		if err != nil {
			t.Error("Expected token to be present in request")
			return
		}

		if !token.Valid {
			t.Error("Expected token in request to be valid")
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if claims["foo"] != "bar" {
				t.Errorf("Expected claim foo in %v", claims)
				return
			}
		} else {
			t.Error("Expected claims, but none found")
		}
	})

	New(jwtHandler)(handler).ServeHTTP(w, r)
}

func TestSign_FromRequestContext(t *testing.T) {
	t.Parallel()

	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+jwtTokenString)

	w := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := Sign(r.Context(), jwt.MapClaims{"jti": "test"})
		if err != nil {
			t.Errorf("Didn't expect sign to error, got: %v", err)
			return
		}

		fmt.Fprint(w, token)
	})

	New(jwtHandler)(handler).ServeHTTP(w, r)

	bytes, _ := ioutil.ReadAll(w.Body)
	if len(bytes) == 0 {
		t.Error("Expected a token, but got empty response")
	}
}

func generateStringToken(m Handler, claims jwt.Claims) string {
	token := jwt.NewWithClaims(m.SigningMethod, claims)

	secret, err := m.Secret(nil)
	if err != nil {
		panic(err)
	}

	tokenString, err := token.SignedString(secret)
	if err != nil {
		panic(err)
	}

	return tokenString
}
