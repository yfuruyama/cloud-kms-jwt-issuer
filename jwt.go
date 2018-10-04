package app

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type JwtHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type JwtBody struct {
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Sub string `json:"sub"`
}

type VerifyResult struct {
	Header JwtHeader
	Body   JwtBody
}

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

// func VerifyJwt(jwt string, jwkSet JwkSet) (*VerifyResult, error) {
// }

func PublicKeyToJwk(publicKey *kmspb.PublicKey, kid string) (*Jwk, error) {
	if alg := publicKey.GetAlgorithm(); alg != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 {
		return nil, errors.New(fmt.Sprintf("Unsupported algorithm: %d", alg))
	}

	pubkeyPem := publicKey.GetPem()
	block, _ := pem.Decode([]byte(pubkeyPem))
	if block == nil {
		return nil, errors.New("invalid public key: " + pubkeyPem)
	}

	keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, _ := keyInterface.(*rsa.PublicKey)

	return &Jwk{
		Kid: kid,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   encodeBase64urlUint(key.N),
		E:   encodeBase64urlUint(key.E),
	}, nil
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
