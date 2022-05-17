package verifyAuth

import (
	"fmt"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt"
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

func IsAuthorizedAdmin(endpoint func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
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
				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					usuariId := claims["UsuariId"]
					if usuariId == "8" {
						endpoint(w, r)
					} else {
						http.Error(w, "Not authorized", http.StatusUnauthorized)
					}
				}
			}
		} else {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
		}
	})
}

// Get the claims from the (already verified) token in the HTTP request headerdfgfds
func GetClaims(r *http.Request) (jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(r.Header["Authorization"][0], jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	} else {
		return nil, err
	}
}

// Get the claims from the (already verified) token in the HTTP request header
func GetToken(r *http.Request) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(r.Header["Authorization"][0], jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	return token.Raw, nil
}
