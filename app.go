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
		header := struct {
			Typ string `json:"typ"`
			Alg string `json:"alg"`
		}{
			Typ: "JWT",
			Alg: "RS256",
		}
		headerJson, _ := json.Marshal(header)

		body := struct {
			Iat int64  `json:"iat"`
			Sub string `json:"sub"`
		}{
			Iat: time.Now().Unix(),
			Sub: r.RemoteAddr,
		}
		bodyJson, _ := json.Marshal(body)

		headerAndBody := fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(headerJson), base64.RawURLEncoding.EncodeToString(bodyJson))

		kms := NewKms(ctx)
		keyId := os.Getenv("KEY_ID")
		signature, err := kms.Sign(keyId, headerAndBody)
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		token := fmt.Sprintf("%s.%s", headerAndBody, base64.RawURLEncoding.EncodeToString([]byte(signature)))

		fmt.Fprintln(w, token)
	})

	router.Get("/certs", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})

	router.Get("/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})

	http.Handle("/", router)
}
