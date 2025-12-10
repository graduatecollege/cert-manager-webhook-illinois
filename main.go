package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our Infoblox DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	cmd.RunWebhookServer(GroupName,
		&infobloxDNSProviderSolver{},
	)
}

// infobloxDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for Infoblox DNS provider.
type infobloxDNSProviderSolver struct {
	client kubernetes.Interface
}

// SecretKeySelector is a reference to a secret key
type SecretKeySelector struct {
	// Name is the name of the secret
	Name string `json:"name"`
	// Key is the key of the secret to select from
	Key string `json:"key"`
}

// infobloxDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
type infobloxDNSProviderConfig struct {
	// Host is the Infoblox WAPI host (e.g., ipam.illinois.edu or dev.ipam.illinois.edu)
	Host string `json:"host"`
	// Version is the WAPI version (e.g., v2.12)
	Version string `json:"version,omitempty"`
	// View is the DNS view (default: "default")
	View string `json:"view,omitempty"`
	// TTL is the DNS record TTL in seconds (default: 300)
	TTL int `json:"ttl,omitempty"`
	// UsernameSecretRef references a Secret containing the username
	UsernameSecretRef SecretKeySelector `json:"usernameSecretRef"`
	// PasswordSecretRef references a Secret containing the password
	PasswordSecretRef SecretKeySelector `json:"passwordSecretRef"`
	// SkipTLSVerify skips TLS certificate verification (default: false)
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
func (c *infobloxDNSProviderSolver) Name() string {
	return "infoblox"
}

// Present is responsible for actually presenting the DNS record with the
// Infoblox DNS provider.
func (c *infobloxDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	username, password, err := c.getCredentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("error getting credentials: %v", err)
	}

	client := c.newHTTPClient(cfg)

	// Extract the record name from the FQDN
	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	// Check if record already exists
	existingRecords, err := c.getTXTRecords(client, cfg, username, password, recordName)
	if err != nil {
		return fmt.Errorf("error checking existing records: %v", err)
	}

	// If a record with this exact value already exists, don't create a duplicate
	for _, record := range existingRecords {
		if record.Text == ch.Key {
			log.Printf("TXT record already exists for %s with value %s", recordName, ch.Key)
			return nil
		}
	}

	// Create the TXT record
	err = c.createTXTRecord(client, cfg, username, password, recordName, ch.Key)
	if err != nil {
		return fmt.Errorf("error creating TXT record: %v", err)
	}

	log.Printf("Successfully created TXT record for %s", recordName)
	return nil
}

// CleanUp should delete the relevant TXT record from the Infoblox DNS provider.
func (c *infobloxDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	username, password, err := c.getCredentials(cfg, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("error getting credentials: %v", err)
	}

	client := c.newHTTPClient(cfg)

	// Extract the record name from the FQDN
	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	// Get existing records
	existingRecords, err := c.getTXTRecords(client, cfg, username, password, recordName)
	if err != nil {
		return fmt.Errorf("error getting existing records: %v", err)
	}

	// Delete only the record with the matching key
	for _, record := range existingRecords {
		if record.Text == ch.Key {
			err = c.deleteTXTRecord(client, cfg, username, password, record.Ref)
			if err != nil {
				return fmt.Errorf("error deleting TXT record: %v", err)
			}
			log.Printf("Successfully deleted TXT record for %s", recordName)
			return nil
		}
	}

	// Record not found, but that's okay (idempotent)
	log.Printf("TXT record not found for %s with value %s, already cleaned up", recordName, ch.Key)
	return nil
}

// Initialize will be called when the webhook first starts.
func (c *infobloxDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %v", err)
	}

	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (infobloxDNSProviderConfig, error) {
	cfg := infobloxDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, fmt.Errorf("no configuration provided")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	// Set defaults
	if cfg.Version == "" {
		cfg.Version = "v2.12"
	}
	if cfg.View == "" {
		cfg.View = "default"
	}
	if cfg.TTL == 0 {
		cfg.TTL = 300
	}

	// Validate required fields
	if cfg.Host == "" {
		return cfg, fmt.Errorf("host is required")
	}
	if cfg.UsernameSecretRef.Name == "" || cfg.UsernameSecretRef.Key == "" {
		return cfg, fmt.Errorf("usernameSecretRef is required")
	}
	if cfg.PasswordSecretRef.Name == "" || cfg.PasswordSecretRef.Key == "" {
		return cfg, fmt.Errorf("passwordSecretRef is required")
	}

	return cfg, nil
}

// getCredentials retrieves the username and password from Kubernetes secrets
func (c *infobloxDNSProviderSolver) getCredentials(cfg infobloxDNSProviderConfig, namespace string) (string, string, error) {
	ctx := context.Background()

	// Get username from secret
	usernameSecret, err := c.client.CoreV1().Secrets(namespace).Get(ctx, cfg.UsernameSecretRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("error getting username secret: %v", err)
	}
	username, ok := usernameSecret.Data[cfg.UsernameSecretRef.Key]
	if !ok {
		return "", "", fmt.Errorf("key %s not found in username secret", cfg.UsernameSecretRef.Key)
	}

	// Get password from secret
	passwordSecret, err := c.client.CoreV1().Secrets(namespace).Get(ctx, cfg.PasswordSecretRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("error getting password secret: %v", err)
	}
	password, ok := passwordSecret.Data[cfg.PasswordSecretRef.Key]
	if !ok {
		return "", "", fmt.Errorf("key %s not found in password secret", cfg.PasswordSecretRef.Key)
	}

	return string(username), string(password), nil
}

// newHTTPClient creates a new HTTP client with optional TLS verification skip
func (c *infobloxDNSProviderSolver) newHTTPClient(cfg infobloxDNSProviderConfig) *http.Client {
	if cfg.SkipTLSVerify {
		// WARNING: InsecureSkipVerify disables TLS certificate validation
		// This creates a security vulnerability allowing man-in-the-middle attacks
		// Only use this for testing purposes with self-signed certificates
		log.Printf("WARNING: TLS certificate verification is disabled")
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return http.DefaultClient
}

// InfobloxTXTRecord represents a TXT record in Infoblox
type InfobloxTXTRecord struct {
	Ref  string `json:"_ref,omitempty"`
	Name string `json:"name"`
	Text string `json:"text"`
	View string `json:"view"`
	TTL  int    `json:"ttl,omitempty"`
}

// getTXTRecords retrieves existing TXT records for a given name
func (c *infobloxDNSProviderSolver) getTXTRecords(client *http.Client, cfg infobloxDNSProviderConfig, username, password, name string) ([]InfobloxTXTRecord, error) {
	url := fmt.Sprintf("https://%s/wapi/%s/record:txt?name=%s&view=%s", cfg.Host, cfg.Version, name, cfg.View)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get TXT records: status %d, body: %s", resp.StatusCode, string(body))
	}

	var records []InfobloxTXTRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, err
	}

	return records, nil
}

// createTXTRecord creates a new TXT record in Infoblox
func (c *infobloxDNSProviderSolver) createTXTRecord(client *http.Client, cfg infobloxDNSProviderConfig, username, password, name, text string) error {
	url := fmt.Sprintf("https://%s/wapi/%s/record:txt", cfg.Host, cfg.Version)

	record := InfobloxTXTRecord{
		Name: name,
		Text: text,
		View: cfg.View,
		TTL:  cfg.TTL,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to create TXT record: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// deleteTXTRecord deletes a TXT record from Infoblox using its reference
func (c *infobloxDNSProviderSolver) deleteTXTRecord(client *http.Client, cfg infobloxDNSProviderConfig, username, password, ref string) error {
	url := fmt.Sprintf("https://%s/wapi/%s/%s", cfg.Host, cfg.Version, ref)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete TXT record: status %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}
