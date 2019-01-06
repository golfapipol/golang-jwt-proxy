package middleware

import (
	"errors"
	"jwtproxy/jwt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func JWTAuthenMiddleware(next http.Handler, now func() time.Time, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := GetAuthToken(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}
		data, err := jwt.Check(token, secret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}
		expiredUnix, _ := strconv.ParseInt(data.ExpiredAt, 10, 64)
		if now().Unix() > expiredUnix {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("token is expired"))
			return
		}

		next.ServeHTTP(w, r)
	}
}

func GetAuthToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}
