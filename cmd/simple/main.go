package main

import (
	"encoding/json"
	"fmt"
	"jwtproxy/jwt"
	"jwtproxy/middleware"
	"net/http"
	"strconv"
	"time"
)

const port = ":4000"
const secret = "terces"

func main() {
	http.HandleFunc("/authen", func(w http.ResponseWriter, r *http.Request) {
		var data map[string]interface{}
		json.NewDecoder(r.Body).Decode(&data)

		token, err := jwt.GenerateJWT(time.Now(), data, secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response := map[string]interface{}{
			"token": token,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		token, err := middleware.GetAuthToken(r)
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	})

	http.HandleFunc("/helloworld", authMiddleware(helloworldHandler, time.Now))
	http.ListenAndServe(port, nil)
}

func authMiddleware(next http.HandlerFunc, now func() time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := middleware.GetAuthToken(r)
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
		fmt.Println("expired time", expiredUnix, now().Unix())
		if now().Unix() > expiredUnix {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("token is expired"))
			return
		}

		if _, existed := data.Payload.(map[string]interface{})["admin"]; !existed {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		next.ServeHTTP(w, r)
	}
}

func helloworldHandler(w http.ResponseWriter, r *http.Request) {
	token, err := middleware.GetAuthToken(r)
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
	response := map[string]interface{}{
		"message": fmt.Sprintf("Hello world %s", data.Payload.(map[string]interface{})["admin"]),
	}
	json.NewEncoder(w).Encode(response)
}
