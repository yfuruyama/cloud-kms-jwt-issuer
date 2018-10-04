package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"google.golang.org/appengine"
)

func init() {
	router := chi.NewRouter()

	router.Post("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		keyId := os.Getenv("KEY_ID")

		token, err := GenerateToken(ctx, keyId, r.RemoteAddr)
		if err != nil {
			handleError(w, err)
			return
		}

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
			Keys: []*Jwk{jwk},
		}

		resp, _ := json.MarshalIndent(jwkSet, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "%s\n", string(resp))
	})

	router.Get("/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)

		token := r.URL.Query().Get("token")
		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

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
			Keys: []*Jwk{jwk},
		}

		// verify token
		result, err := VerifyToken(token, jwkSet)
		if err != nil {
			handleError(w, err)
			return
		}

		// return response
		if result.Valid {
			tokeninfo := struct {
				Active bool   `json:"active"`
				Iat    int64  `json:"iat"`
				Exp    int64  `json:"exp"`
				Sub    string `json:"sub"`
			}{
				Active: true,
				Iat:    result.Body.Iat,
				Exp:    result.Body.Exp,
				Sub:    result.Body.Sub,
			}
			resp, _ := json.MarshalIndent(tokeninfo, "", "  ")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, "%s\n", string(resp))
		} else {
			log.Printf("verification failed: %s\n", result.ErrorDetail)
			tokeninfo := struct {
				Active bool `json:"active"`
			}{
				Active: false,
			}
			resp, _ := json.MarshalIndent(tokeninfo, "", "  ")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, "%s\n", string(resp))
		}
	})

	http.Handle("/", router)
}

func handleError(w http.ResponseWriter, err error) {
	log.Print(err)
	w.WriteHeader(http.StatusInternalServerError)
}
