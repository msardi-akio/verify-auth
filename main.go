package verifyAuth

import (
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
)

var mySigningKey = []byte(os.Getenv("JWT_SIGNKEY"))

func IsAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Authorization"] != nil {

			token, err := jwt.Parse(r.Header["Authorization"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("there was an error")
				}
				return mySigningKey, nil
			})

			if err != nil {
				http.Error(w, "Not authorized", http.StatusUnauthorized)
			}

			if token.Valid {
				endpoint(w, r)
			}
		} else {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
		}
	})
}
