// Package jaws introduces a simple JWT authentication middleware.
//
// You can use it with routers like github.com/go-chi/chi. Jaws also provides
// request scoped utilities for JWT token signing and mocking for easier
// testing.
//
// To use jaws, you need to attach the middleware into the middleware chain.
//
//	router.Use(jaws.New(jaws.Handler{
//		Secret: os.Getenv("JWT_SECRET"),
//		SigningMethod: jwt.SigningMethodHS256
//	}))
//
// The middleware can extract tokens attached at the Authorization HTTP header.
// Tokens should be in the form of:
//
//	Authorization: Bearer xxx.yyy.zzz
//
// Attaching the middleware can panic on insufficient configuration parameters,
// to help you catch configurations errors earlier.
//
// Once attached, you can use the following utilities to decode a token and
// authenticate a user.
//
//	func AuthHandler(w http.ResponseWriter, r *http.Request) {
//		// Extract the claims out of the token in Authorization: Bearer x.y.z
//		claims, err := jaws.Claims(r.Context())
//		if err != nil {
//			http.Error(w, "Unauthorized", http.StatusUnauthorized)
//			return
//		}
//
//		// Find the user in claims["jti"] for example.
//	}
//
// The code below can be used to sign a new token.
//
//	func LoginHandler(w http.ResponseWriter, r *http.Request) {
//		jaws.Sign(r.Context(), jwt.StandardClaims{
//			Id:        "user id found if properly authenticated",
//			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
//		})
//	}
//
// Explore the publicly documented functions and structures for more information.
package jaws
