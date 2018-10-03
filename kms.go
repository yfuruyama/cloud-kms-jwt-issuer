package app

import (
	"context"
	"crypto/sha256"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type Kms struct {
	ctx context.Context
}

func NewKms(ctx context.Context) *Kms {
	return &Kms{ctx}
}

func (k *Kms) Sign(keyId string, text string) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(k.ctx)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(text))
	digestSlice := digest[:]
	req := &kmspb.AsymmetricSignRequest{
		Name: keyId,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{digestSlice},
		},
	}

	resp, err := client.AsymmetricSign(k.ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil
}

func (k *Kms) GetPublicKey(keyId string) (*kmspb.PublicKey, error) {
	client, err := kms.NewKeyManagementClient(k.ctx)
	if err != nil {
		return nil, err
	}

	req := &kmspb.GetPublicKeyRequest{
		Name: keyId,
	}

	return client.GetPublicKey(k.ctx, req)
}
