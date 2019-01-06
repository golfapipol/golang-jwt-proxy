package main

import (
	"encoding/json"
	"jwtproxy/jwt"
	"jwtproxy/middleware"
	"net/http"
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

	http.ListenAndServe(port, nil)
}
