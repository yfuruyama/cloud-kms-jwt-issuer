package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"regexp"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type Kms struct {
	ctx context.Context
}

func NewKms(ctx context.Context) *Kms {
	return &Kms{ctx}
}

func (k *Kms) Sign(keyResourceId string, text string) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(k.ctx)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(text))
	digestSlice := digest[:]
	req := &kmspb.AsymmetricSignRequest{
		Name: keyResourceId,
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

func (k *Kms) GetPublicKey(keyResourceId string) (*kmspb.PublicKey, error) {
	client, err := kms.NewKeyManagementClient(k.ctx)
	if err != nil {
		return nil, err
	}

	req := &kmspb.GetPublicKeyRequest{
		Name: keyResourceId,
	}

	return client.GetPublicKey(k.ctx, req)
}

func KeyResourceIdToKid(keyResourceId string) (string, error) {
	// Key Resource ID format: projects/{project_id}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
	re := regexp.MustCompile("projects/(.+)/locations/(.+)/keyRings/(.+)/cryptoKeys/(.+)/cryptoKeyVersions/(.+)")
	matched := re.FindStringSubmatch(keyResourceId)
	if len(matched) != 6 {
		return "", errors.New("invalid key resource id")
	}
	return matched[5], nil
}
