/*
Copyright 2025.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ClusterRegistryCredentialSpec defines the desired state of ClusterRegistryCredential
type ClusterRegistryCredentialSpec struct {
	// Provider contains the configuration for the registry provider.
	// +kubebuilder:validation:Required
	Provider ProviderSpec `json:"provider"`

	// Decryption contains the configuration for decrypting the provider spec.
	// +optional
	Decryption *DecryptionSpec `json:"decryption,omitempty"`

	// Rotation contains the policy for rotating the credentials.
	// +optional
	Rotation *RotationPolicy `json:"rotation,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Templates []SecretTemplateSpec `json:"templates"`
}

// ProviderSpec defines the configuration for a specific registry provider.
// Only one provider can be configured.
type ProviderSpec struct {
	// GHCR provides credentials for the GitHub Container Registry.
	// +optional
	GHCR *GHCRProvider `json:"ghcr,omitempty"`
}

// GHCRProvider defines the configuration for the GHCR provider using a GitHub App.
// The PrivateKey for the app should be provided in the top-level 'sops' block.
type GHCRProvider struct {
	// AppID is the unique identifier for the GitHub App.
	// +kubebuilder:validation:Required
	AppID string `json:"appId"`

	// InstallationID is the identifier for the installation of the GitHub App.
	// +kubebuilder:validation:Required
	InstallationID string `json:"installationId"`

	// Permissions specifies the permissions to request for the installation token.
	// +optional
	Permissions map[string]string `json:"permissions,omitempty"`

	// PrivateKey is the RSA private key of the GitHub App.
	// This field is populated by the controller after SOPS decryption.
	// It should be present in the 'sops' block of the CR, not set directly.
	// +optional
	PrivateKey string `json:"privateKey,omitempty"`

	// Registry is the container registry endpoint.
	// Defaults to "ghcr.io" if not specified.
	// +optional
	Registry string `json:"registry,omitempty"`

	// APIEndpoint is the GitHub API endpoint.
	// Defaults to "https'://api.github.com" if not specified.
	// +optional
	APIEndpoint string `json:"apiEndpoint,omitempty"`
}

// DecryptionSpec defines how to decrypt the provider configuration.
type DecryptionSpec struct {
	// Provider is the decryption provider to use, e.g., "sops".
	// +kubebuilder:validation:Required
	Provider string `json:"provider"`
}

// SecretTemplateSpec defines a template and the list of targets it applies to.
type SecretTemplateSpec struct {
	// Name is a logical name for this template group (e.g., "dockerconfig-logins")
	// +optional
	Name string `json:"name,omitempty"`

	// Type is the type of the Kubernetes Secret (e.g., "Opaque", "kubernetes.io/dockerconfigjson").
	// +kubebuilder:validation:Required
	// +kubebuilder:default:="kubernetes.io/dockerconfigjson"
	Type string `json:"type"`

	// Metadata contains optional labels and annotations to merge into the target Secrets.
	// +optional
	Metadata *TemplateMetadata `json:"metadata,omitempty"`

	// Data contains the string templates for the Secret's data map.
	// The templates are rendered using Go's text/template engine.
	// Available variables: .Token, .Username, .DockerConfigJSON, .ExpiresAtRFC3339, .Registry
	// +kubebuilder:validation:Required
	Data map[string]string `json:"data"`

	// Targets is the list of Secrets to create using this template.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Targets []SecretTarget `json:"targets"`
}

// SecretTarget defines the name and namespace of a target Secret.
type SecretTarget struct {
	// Name of the Secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the Secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// TemplateMetadata contains metadata for the generated secret.
type TemplateMetadata struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// RotationPolicy defines how credentials should be rotated.
type RotationPolicy struct {
	// RotateBefore is the duration before token expiration to trigger a rotation.
	// Defaults to "15m".
	// +optional
	RotateBefore *metav1.Duration `json:"rotateBefore,omitempty"`
}

// ClusterRegistryCredentialStatus defines the observed state of ClusterRegistryCredential
type ClusterRegistryCredentialStatus struct {
	// Conditions represent the latest available observations of the resource's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastRotationTime is the timestamp of the last successful token rotation.
	// +optional
	LastRotationTime *metav1.Time `json:"lastRotationTime,omitempty"`

	// TokenExpirationTime is the timestamp when the current token expires.
	// +optional
	TokenExpirationTime *metav1.Time `json:"tokenExpirationTime,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster,shortName=crc
//+kubebuilder:metadata:annotations="api-approved.kubernetes.io=unapproved"

// ClusterRegistryCredential is the Schema for the clusterregistrycredentials API
type ClusterRegistryCredential struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterRegistryCredentialSpec `json:"spec,omitempty"`
	// +optional
	Status ClusterRegistryCredentialStatus `json:"status,omitempty"`

	// Sops contains the SOPS metadata block for decryption
	// This field is managed by SOPS and should not be edited manually.
	// +optional
	Sops *runtime.RawExtension `json:"sops,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterRegistryCredentialList contains a list of ClusterRegistryCredential
type ClusterRegistryCredentialList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterRegistryCredential `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterRegistryCredential{}, &ClusterRegistryCredentialList{})
}
