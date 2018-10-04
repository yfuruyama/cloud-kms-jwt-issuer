package app

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi"
	"google.golang.org/appengine"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type JwkSet struct {
	Keys []Jwk `json:"keys"`
}

type Jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

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
		if alg := publicKey.GetAlgorithm(); alg != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 {
			handleError(w, errors.New(fmt.Sprintf("Unsupported algorithm: %d", alg)))
			return
		}

		pubkeyPem := publicKey.GetPem()
		log.Print(pubkeyPem)

		block, _ := pem.Decode([]byte(pubkeyPem))
		if block == nil {
			handleError(w, errors.New("invalid public key: "+pubkeyPem))
			return
		}

		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			handleError(w, err)
			return
		}
		key, _ := keyInterface.(*rsa.PublicKey)

		jwkSet := JwkSet{
			Keys: []Jwk{
				Jwk{
					Kid: keyId,
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
					N:   encodeBase64urlUint(key.N),
					E:   encodeBase64urlUint(key.E),
				},
			},
		}

		resp, _ := json.MarshalIndent(jwkSet, "", "  ")
		fmt.Fprint(w, string(resp))
	})

	router.Get("/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})

	http.Handle("/", router)
}

func handleError(w http.ResponseWriter, err error) {
	log.Print(err)
	w.WriteHeader(http.StatusInternalServerError)
}

// see. https://tools.ietf.org/html/rfc7518#section-2
func encodeBase64urlUint(data interface{}) string {
	var byteArray []byte

	switch v := data.(type) {
	case int:
		d := data.(int)
		log.Println(d)
		byteArray = make([]byte, 8)
		binary.BigEndian.PutUint64(byteArray, uint64(d))
		log.Printf("%#v\n", byteArray)
	case *big.Int:
		d := data.(*big.Int)
		byteArray = d.Bytes()
	default:
		panic(fmt.Sprintf("unexpected type: %T", v))
	}

	i := 0
	for ; i < len(byteArray); i++ {
		if byteArray[i] != 0 {
			break
		}
	}

	return base64.RawURLEncoding.EncodeToString(byteArray[i:])
}
