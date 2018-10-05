package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"google.golang.org/appengine/log"

	"github.com/go-chi/chi"
	"google.golang.org/appengine"
)

func init() {
	router := chi.NewRouter()
	config := GetConfig()

	router.Post("/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		sub := r.FormValue("sub")

		result, err := GenerateToken(ctx, config.KeyResourceId, sub)
		if err != nil {
			handleError(ctx, w, err)
			return
		}

		resp, _ := json.MarshalIndent(result, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "%s\n", string(resp))
	})

	router.Get("/certs", func(w http.ResponseWriter, r *http.Request) {
		ctx := appengine.NewContext(r)
		kms := NewKms(ctx)
		publicKey, err := kms.GetPublicKey(config.KeyResourceId)
		if err != nil {
			handleError(ctx, w, err)
			return
		}

		jwk, err := PublicKeyToJwk(publicKey, config.KeyResourceId)
		if err != nil {
			handleError(ctx, w, err)
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

		// get current key set
		kms := NewKms(ctx)
		publicKey, err := kms.GetPublicKey(config.KeyResourceId)
		if err != nil {
			handleError(ctx, w, err)
			return
		}

		jwk, err := PublicKeyToJwk(publicKey, config.KeyResourceId)
		if err != nil {
			handleError(ctx, w, err)
			return
		}

		jwkSet := JwkSet{
			Keys: []*Jwk{jwk},
		}

		// verify token
		token := r.URL.Query().Get("token")
		result, err := VerifyToken(token, jwkSet)
		if err != nil {
			handleError(ctx, w, err)
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
			log.Infof(ctx, "verification failed: %s\n", result.ErrorDetail)
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

func handleError(ctx context.Context, w http.ResponseWriter, err error) {
	log.Errorf(ctx, "%s", err)
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "%s\n", http.StatusText(http.StatusInternalServerError))
}
