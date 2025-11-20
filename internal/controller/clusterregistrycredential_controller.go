/*
Copyright 2025.
*/

package controller

import (
	"bytes"
	"context"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	txtTemplate "text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/golang-jwt/jwt/v5"
	credsv1alpha1 "github.com/vibe/registry-operator/api/v1alpha1"
)

const (
	ConditionTypeReady = "Ready"
	RequeueTimeBuffer  = 1 * time.Minute

	fieldOwner           = "registry-operator"
	labelManagedBy       = "app.kubernetes.io/managed-by"
	managedByValue       = "registry-operator"
	annotationExpiresAt  = "registry.k8s.io/token-expiresAt" // RFC3339
	annotationRotationID = "registry.k8s.io/rotationId"      // RFC3339Nano
)

type ClusterRegistryCredentialReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	cache         *tokenCache
	httpClient    *http.Client
	sopsDecryptor *SopsDecryptor
}

type tokenData struct {
	token      string
	expiresAt  *time.Time
	rotationID string
	needMint   bool
	now        time.Time
}

//+kubebuilder:rbac:groups=registry.k8s.io,resources=clusterregistrycredentials,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=registry.k8s.io,resources=clusterregistrycredentials/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=registry.k8s.io,resources=clusterregistrycredentials/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *ClusterRegistryCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Starting reconciliation for ClusterRegistryCredential")

	resource := &credsv1alpha1.ClusterRegistryCredential{}
	if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("ClusterRegistryCredential not found (deleted)")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get ClusterRegistryCredential")
		return ctrl.Result{}, err
	}

	activeResource := resource.DeepCopy()
	var err error

	if resource.Spec.Decryption != nil && resource.Spec.Decryption.Provider == "sops" {
		decryptedObj, err := r.sopsDecryptor.Decrypt(ctx, resource, resource.Spec.Decryption, resource.GetNamespace())
		if err != nil {
			return r.handleError(ctx, resource, "DecryptionError", err)
		}

		var ok bool
		activeResource, ok = decryptedObj.(*credsv1alpha1.ClusterRegistryCredential)
		if !ok {
			err = fmt.Errorf("decrypted object was not the expected type *ClusterRegistryCredential")
			return r.handleError(ctx, resource, "DecryptionError", err)
		}
	}

	td, err := r.resolveToken(ctx, activeResource)
	if err != nil {
		return r.handleError(ctx, resource, "ProviderError", err)
	}

	for _, template := range activeResource.Spec.Templates {
		for _, target := range template.Targets {
			err := r.reconcileTargetSecret(ctx, resource, activeResource, template, target, td)
			if err != nil {
				return r.handleError(ctx, resource, "SecretManagementError", err)
			}
		}
	}

	if err := r.updateSuccessStatus(ctx, resource, td); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	requeueAfter := r.calculateRequeue(ctx, activeResource, td.expiresAt)
	logger.Info("Reconciliation successful", "requeue_after", requeueAfter.String())

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *ClusterRegistryCredentialReconciler) updateSuccessStatus(ctx context.Context, resource *credsv1alpha1.ClusterRegistryCredential, td tokenData) error {
	meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
		Type:    ConditionTypeReady,
		Status:  metav1.ConditionTrue,
		Reason:  "Ready",
		Message: "Token applied to all targets",
	})

	if td.needMint {
		resource.Status.LastRotationTime = &metav1.Time{Time: td.now}
	}
	if td.expiresAt != nil {
		resource.Status.TokenExpirationTime = &metav1.Time{Time: *td.expiresAt}
	}

	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		latest := &credsv1alpha1.ClusterRegistryCredential{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(resource), latest); err != nil {
			return err
		}
		patch := client.MergeFrom(latest.DeepCopy())
		latest.Status = resource.Status
		return r.Status().Patch(ctx, latest, patch)
	})
}

func (r *ClusterRegistryCredentialReconciler) calculateRequeue(ctx context.Context, activeResource *credsv1alpha1.ClusterRegistryCredential, expiresAt *time.Time) time.Duration {
	rotateBefore := 15 * time.Minute
	if activeResource.Spec.Rotation != nil && activeResource.Spec.Rotation.RotateBefore != nil {
		rotateBefore = activeResource.Spec.Rotation.RotateBefore.Duration
	}

	poll := time.Minute
	var requeueAfter time.Duration

	if expiresAt == nil || expiresAt.IsZero() {
		requeueAfter = poll
	} else {
		due := expiresAt.Add(-rotateBefore).Add(-RequeueTimeBuffer)
		untilDue := time.Until(due)
		requeueAfter = poll
		if untilDue < poll {
			if untilDue < 0 {
				requeueAfter = 0
			} else {
				requeueAfter = untilDue
			}
		}
	}
	return requeueAfter
}

func (r *ClusterRegistryCredentialReconciler) handleError(ctx context.Context, resource *credsv1alpha1.ClusterRegistryCredential, reason string, err error) (ctrl.Result, error) {
	log.FromContext(ctx).Error(err, "Reconciliation failed", "reason", reason)

	orig := resource.DeepCopy()
	meta.SetStatusCondition(&resource.Status.Conditions, metav1.Condition{
		Type:    ConditionTypeReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: err.Error(),
	})

	_ = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		latest := &credsv1alpha1.ClusterRegistryCredential{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(resource), latest); err != nil {
			log.FromContext(ctx).Error(err, "Failed to get latest resource during error handling")
			return r.Status().Patch(ctx, resource, client.MergeFrom(orig))
		}
		patch := client.MergeFrom(latest.DeepCopy())
		latest.Status = resource.Status
		return r.Status().Patch(ctx, latest, patch)
	})

	return ctrl.Result{}, err
}

func (r *ClusterRegistryCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.cache == nil {
		r.cache = newTokenCache()
	}

	if r.httpClient == nil {
		r.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:        10,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		}
	}

	if r.sopsDecryptor == nil {
		r.sopsDecryptor = NewSopsDecryptor(mgr.GetClient())
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&credsv1alpha1.ClusterRegistryCredential{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *ClusterRegistryCredentialReconciler) resolveToken(ctx context.Context, activeResource *credsv1alpha1.ClusterRegistryCredential) (tokenData, error) {
	logger := log.FromContext(ctx)

	rotateBefore := 15 * time.Minute
	if activeResource.Spec.Rotation != nil && activeResource.Spec.Rotation.RotateBefore != nil {
		rotateBefore = activeResource.Spec.Rotation.RotateBefore.Duration
	}
	now := time.Now()
	cacheKey := string(activeResource.UID)

	td := tokenData{now: now}

	if v, ok := r.cache.Get(cacheKey); ok {
		logger.Info("Token found in cache")

		due := v.expiresAt.Add(-rotateBefore).Add(-RequeueTimeBuffer)
		if now.Before(due) {
			logger.Info("Using cached token")
			td.token = v.token
			td.expiresAt = &v.expiresAt
			td.rotationID = v.rotationID
			td.needMint = false
			return td, nil
		}
		logger.Info("Cached token is due for rotation")
		td.needMint = true
	} else {
		logger.Info("Cache miss, will mint new token")
		td.needMint = true
	}

	logger.Info("Minting new token")
	newToken, newExp, err := r.getTokenForProvider(ctx, &activeResource.Spec.Provider)
	if err != nil {
		return tokenData{}, err
	}
	td.token = newToken
	td.expiresAt = newExp
	td.rotationID = now.UTC().Format(time.RFC3339Nano)

	r.cache.Set(cacheKey, cachedToken{
		token:      td.token,
		expiresAt:  *td.expiresAt,
		rotationID: td.rotationID,
	})

	return td, nil
}

func (r *ClusterRegistryCredentialReconciler) getTokenForProvider(ctx context.Context, provider *credsv1alpha1.ProviderSpec) (string, *time.Time, error) {
	if provider.GHCR != nil {
		return r.getGHCRToken(ctx, provider.GHCR)
	}
	return "", nil, fmt.Errorf("no provider specified in spec")
}

func (r *ClusterRegistryCredentialReconciler) getGHCRToken(ctx context.Context, ghcr *credsv1alpha1.GHCRProvider) (string, *time.Time, error) {
	var privateKeyBytes []byte

	if ghcr.PrivateKey != "" {
		privateKeyBytes = []byte(ghcr.PrivateKey)
	} else {
		return "", nil, fmt.Errorf("no private key provided for GHCR provider")
	}

	signingKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	claims := &jwt.RegisteredClaims{
		Issuer:    ghcr.AppID,
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}

	signedJWT, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	apiEndpoint := ghcr.APIEndpoint
	if apiEndpoint == "" {
		apiEndpoint = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", apiEndpoint, ghcr.InstallationID)

	var reqBody io.Reader
	if ghcr.Permissions != nil && len(ghcr.Permissions) > 0 {
		bodyMap := map[string]interface{}{
			"permissions": ghcr.Permissions,
		}
		jsonBody, err := json.Marshal(bodyMap)
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal permissions for token request: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+signedJWT)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to request installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("failed to get installation token, status %d: %s %s", resp.StatusCode, ghcr.InstallationID, string(body))
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("failed to decode installation token response: %w", err)
	}

	return result.Token, &result.ExpiresAt, nil
}

func (r *ClusterRegistryCredentialReconciler) reconcileTargetSecret(ctx context.Context,
	owner *credsv1alpha1.ClusterRegistryCredential,
	activeResource *credsv1alpha1.ClusterRegistryCredential,
	template credsv1alpha1.SecretTemplateSpec,
	target credsv1alpha1.SecretTarget,
	td tokenData,
) error {
	registry := ""
	if activeResource.Spec.Provider.GHCR != nil {
		registry = activeResource.Spec.Provider.GHCR.Registry
	}

	dockerConfigJSON, err := generateDockerConfigJSON(td.token, registry)
	if err != nil {
		return fmt.Errorf("failed to generate dockerConfigJSON: %w", err)
	}

	templateData := map[string]string{
		"Token":            td.token,
		"Username":         "x-access-token",
		"DockerConfigJSON": dockerConfigJSON,
		"ExpiresAtRFC3339": td.expiresAt.UTC().Format(time.RFC3339),
		"Registry":         registry,
	}

	secretData := make(map[string][]byte)
	for key, valTpl := range template.Data {
		tmpl, err := txtTemplate.New(key).Option("missingkey=error").Parse(valTpl)
		if err != nil {
			return fmt.Errorf("failed to parse template for key %s: %w", key, err)
		}
		var renderedValue bytes.Buffer
		if err := tmpl.Execute(&renderedValue, templateData); err != nil {
			return fmt.Errorf("failed to execute template for key %s: %w", key, err)
		}
		secretData[key] = renderedValue.Bytes()
	}

	desired := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.Name,
			Namespace: target.Namespace,
			Labels: map[string]string{
				labelManagedBy: managedByValue,
			},
			Annotations: map[string]string{
				annotationExpiresAt:  td.expiresAt.UTC().Format(time.RFC3339),
				annotationRotationID: td.rotationID,
			},
		},
		Type: corev1.SecretType(template.Type),
		Data: secretData,
	}

	if template.Metadata != nil {
		if desired.ObjectMeta.Labels == nil {
			desired.ObjectMeta.Labels = map[string]string{}
		}
		for k, v := range template.Metadata.Labels {
			desired.ObjectMeta.Labels[k] = v
		}
		if desired.ObjectMeta.Annotations == nil {
			desired.ObjectMeta.Annotations = map[string]string{}
		}
		for k, v := range template.Metadata.Annotations {
			desired.ObjectMeta.Annotations[k] = v
		}
		desired.ObjectMeta.Labels[labelManagedBy] = managedByValue
		desired.ObjectMeta.Annotations[annotationExpiresAt] = td.expiresAt.UTC().Format(time.RFC3339)
		desired.ObjectMeta.Annotations[annotationRotationID] = td.rotationID
	}

	if err := ctrl.SetControllerReference(owner, desired, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference: %w", err)
	}

	if err := r.Patch(ctx, desired, client.Apply, client.FieldOwner(fieldOwner), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply Secret %s/%s: %w", target.Namespace, target.Name, err)
	}

	return nil
}

func generateDockerConfigJSON(token, registry string) (string, error) {
	if registry == "" {
		registry = "ghcr.io"
	}

	authString := fmt.Sprintf("x-access-token:%s", token)
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authString))

	dockerConfig := map[string]interface{}{
		"auths": map[string]interface{}{
			registry: map[string]interface{}{
				"auth": encodedAuth,
			},
		},
	}

	jsonBytes, err := json.Marshal(dockerConfig)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

type cachedToken struct {
	token      string
	expiresAt  time.Time
	rotationID string
}

type tokenCache struct {
	mu   sync.RWMutex
	data map[string]cachedToken
}

func newTokenCache() *tokenCache {
	return &tokenCache{data: make(map[string]cachedToken)}
}

func (c *tokenCache) Get(uid string) (cachedToken, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.data[uid]
	return v, ok
}

func (c *tokenCache) Set(uid string, ct cachedToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[uid] = ct
}
