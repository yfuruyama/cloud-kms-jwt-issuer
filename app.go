package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi"
	"google.golang.org/appengine"
)

func init() {
	router := chi.NewRouter()

	router.Get("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		keyId := os.Getenv("KEY_ID")

		header := struct {
			Typ string `json:"typ"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
		}{
			Typ: "JWT",
			Alg: "RS256",
			Kid: keyId,
		}
		headerJson, _ := json.Marshal(header)

		body := struct {
			Iat int64  `json:"iat"`
			Exp int64  `json:"exp"`
			Sub string `json:"sub"`
		}{
			Iat: time.Now().Unix(),
			Exp: time.Now().Unix() + 900,
			Sub: r.RemoteAddr,
		}
		bodyJson, _ := json.Marshal(body)

		headerAndBody := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(headerJson), base64.RawURLEncoding.EncodeToString(bodyJson))

		kms := NewKms(ctx)
		signature, err := kms.Sign(keyId, headerAndBody)
		if err != nil {
			handleError(w, err)
			return
		}

		token := fmt.Sprintf("%s.%s", headerAndBody, base64.RawURLEncoding.EncodeToString([]byte(signature)))

		fmt.Fprintln(w, token)
	})

	router.Get("/certs", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		kms := NewKms(ctx)
		keyId := os.Getenv("KEY_ID")
		publicKey, err := kms.GetPublicKey(keyId)
		if err != nil {
			handleError(w, err)
			return
		}

		jwk, err := PublicKeyToJwk(publicKey, keyId)
		if err != nil {
			handleError(w, err)
			return
		}

		jwkSet := JwkSet{
			Keys: []Jwk{*jwk},
		}

		resp, _ := json.MarshalIndent(jwkSet, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, string(resp))
	})

	router.Get("/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// verify token

		// return token info
		// {
		//   "active": true
		//   "iat": 14000000
		//   "exp": 14000000
		//   "sub": "192.168.1.1"
		// }
	})

	http.Handle("/", router)
}

func handleError(w http.ResponseWriter, err error) {
	log.Print(err)
	w.WriteHeader(http.StatusInternalServerError)
}
