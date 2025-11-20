/*
Copyright 2025.
*/

package controller

import (
	"context"
	"fmt"

	"github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/auth/aws"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	awskms "github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/logging"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	sigsyaml "sigs.k8s.io/yaml"

	credsv1alpha1 "github.com/vibe/registry-operator/api/v1alpha1"
)

type SopsDecryptor struct {
	client client.Client
}

func NewSopsDecryptor(c client.Client) *SopsDecryptor {
	return &SopsDecryptor{client: c}
}

func (d *SopsDecryptor) Decrypt(ctx context.Context,
	encryptedObj runtime.Object,
	decryptionSpec *credsv1alpha1.DecryptionSpec,
	namespace string,
) (runtime.Object, error) {

	logger := log.FromContext(ctx)

	if decryptionSpec == nil {
		return encryptedObj, nil
	}

	logger.Info("Starting SOPS decryption using AWS KMS")

	opts := []auth.Option{
		auth.WithClient(d.client),
	}

	awsCredentialsProvider := func(region string) *awskms.CredentialsProvider {
		awsOpts := append(opts, auth.WithSTSRegion(region))
		provider := aws.NewCredentialsProvider(ctx, awsOpts...)
		return awskms.NewCredentialsProvider(provider)
	}

	server := NewSopsKeyServer(awsCredentialsProvider)
	keyServices := []keyservice.KeyServiceClient{keyservice.NewCustomLocalClient(server)}

	originalAccessor, err := meta.Accessor(encryptedObj)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata accessor for original object: %w", err)
	}
	originalMeta := originalAccessor

	yamlData, err := sigsyaml.Marshal(encryptedObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object to YAML: %w", err)
	}

	store := common.StoreForFormat(formats.Yaml, config.NewStoresConfig())
	tree, err := store.LoadEncryptedFile(yamlData)
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted YAML data: %w", err)
	}

	metadataKey, err := tree.Metadata.GetDataKeyWithKeyServices(keyServices, sops.DefaultDecryptionOrder)
	if err != nil {
		return nil, fmt.Errorf("cannot get sops data key: %w", err)
	}

	cipher := aes.NewCipher()
	if _, err = tree.Decrypt(metadataKey, cipher); err != nil {
		return nil, fmt.Errorf("failed to decrypt SOPS tree: %w", err)
	}

	outputStore := common.StoreForFormat(formats.Yaml, config.NewStoresConfig())
	decryptedYamlBytes, err := outputStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("failed to emit plain file from SOPS tree: %w", err)
	}

	decryptedObj := encryptedObj.DeepCopyObject()

	if err := sigsyaml.Unmarshal(decryptedYamlBytes, decryptedObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted YAML: %w", err)
	}

	decryptedAccessor, err := meta.Accessor(decryptedObj)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata accessor for decrypted object: %w", err)
	}

	decryptedAccessor.SetNamespace(originalMeta.GetNamespace())
	decryptedAccessor.SetName(originalMeta.GetName())
	decryptedAccessor.SetGenerateName(originalMeta.GetGenerateName())
	decryptedAccessor.SetUID(originalMeta.GetUID())
	decryptedAccessor.SetResourceVersion(originalMeta.GetResourceVersion())
	decryptedAccessor.SetGeneration(originalMeta.GetGeneration())
	decryptedAccessor.SetSelfLink(originalMeta.GetSelfLink())
	decryptedAccessor.SetCreationTimestamp(originalMeta.GetCreationTimestamp())
	decryptedAccessor.SetDeletionTimestamp(originalMeta.GetDeletionTimestamp())
	decryptedAccessor.SetDeletionGracePeriodSeconds(originalMeta.GetDeletionGracePeriodSeconds())
	decryptedAccessor.SetLabels(originalMeta.GetLabels())
	decryptedAccessor.SetAnnotations(originalMeta.GetAnnotations())
	decryptedAccessor.SetFinalizers(originalMeta.GetFinalizers())
	decryptedAccessor.SetOwnerReferences(originalMeta.GetOwnerReferences())
	decryptedAccessor.SetManagedFields(originalMeta.GetManagedFields())

	logger.Info("Successfully decrypted resource with SOPS/AWS KMS")
	return decryptedObj, nil
}

type sopsKeyServer struct {
	awsCredentialsProvider func(arn string) *awskms.CredentialsProvider
	defaultServer          keyservice.KeyServiceServer
}

func NewSopsKeyServer(awsProvider func(arn string) *awskms.CredentialsProvider) keyservice.KeyServiceServer {
	logging.SetLevel(0)

	return &sopsKeyServer{
		awsCredentialsProvider: awsProvider,
		defaultServer:          &keyservice.Server{Prompt: false},
	}
}

func (ks sopsKeyServer) Encrypt(ctx context.Context, req *keyservice.EncryptRequest) (*keyservice.EncryptResponse, error) {
	return ks.defaultServer.Encrypt(ctx, req)
}

func (ks sopsKeyServer) Decrypt(ctx context.Context, req *keyservice.DecryptRequest) (*keyservice.DecryptResponse, error) {
	key := req.Key
	switch k := key.KeyType.(type) {
	case *keyservice.Key_KmsKey:
		if ks.awsCredentialsProvider != nil {
			plaintext, err := ks.decryptWithAWSKMS(k.KmsKey, req.Ciphertext)
			if err != nil {
				return nil, err
			}
			return &keyservice.DecryptResponse{
				Plaintext: plaintext,
			}, nil
		}
	case nil:
		return nil, fmt.Errorf("must provide a key")
	}
	return ks.defaultServer.Decrypt(ctx, req)
}

func (ks *sopsKeyServer) decryptWithAWSKMS(key *keyservice.KmsKey, cipherText []byte) ([]byte, error) {
	awsKey := kmsKeyToMasterKey(key)
	awsKey.EncryptedKey = string(cipherText)
	ks.awsCredentialsProvider(key.Arn).ApplyToMasterKey(&awsKey)
	return awsKey.Decrypt()
}

func kmsKeyToMasterKey(key *keyservice.KmsKey) awskms.MasterKey {
	ctx := make(map[string]*string)
	for k, v := range key.Context {
		value := v
		ctx[k] = &value
	}
	return awskms.MasterKey{
		Arn:               key.Arn,
		Role:              key.Role,
		EncryptionContext: ctx,
	}
}
