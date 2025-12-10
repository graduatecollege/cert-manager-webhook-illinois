package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
	httpClient *http.Client
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
	// UsernameFile is the path to the file containing the username (default: /etc/infoblox/username)
	UsernameFile string `json:"usernameFile,omitempty"`
	// PasswordFile is the path to the file containing the password (default: /etc/infoblox/password)
	PasswordFile string `json:"passwordFile,omitempty"`
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

	username, password, err := c.getCredentials(cfg)
	if err != nil {
		return fmt.Errorf("error getting credentials: %v", err)
	}

	// Extract the record name from the FQDN
	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	// Check if record already exists
	existingRecords, err := c.getTXTRecords(cfg, username, password, recordName)
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
	err = c.createTXTRecord(cfg, username, password, recordName, ch.Key)
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

	username, password, err := c.getCredentials(cfg)
	if err != nil {
		return fmt.Errorf("error getting credentials: %v", err)
	}

	// Extract the record name from the FQDN
	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	// Get existing records
	existingRecords, err := c.getTXTRecords(cfg, username, password, recordName)
	if err != nil {
		return fmt.Errorf("error getting existing records: %v", err)
	}

	// Delete only the record with the matching key
	for _, record := range existingRecords {
		if record.Text == ch.Key {
			err = c.deleteTXTRecord(cfg, username, password, record.Ref)
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
	// Create HTTP client with cookie jar for session persistence
	// The Infoblox API returns an "ibapauth" cookie after the first authentication
	// which speeds up subsequent requests
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("error creating cookie jar: %v", err)
	}

	c.httpClient = &http.Client{
		Jar: jar,
	}

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
	if cfg.UsernameFile == "" {
		cfg.UsernameFile = "/etc/infoblox/username"
	}
	if cfg.PasswordFile == "" {
		cfg.PasswordFile = "/etc/infoblox/password"
	}

	// Validate required fields
	if cfg.Host == "" {
		return cfg, fmt.Errorf("host is required")
	}

	return cfg, nil
}

// getCredentials retrieves the username and password from mounted volume files
func (c *infobloxDNSProviderSolver) getCredentials(cfg infobloxDNSProviderConfig) (string, string, error) {
	// Read username from file
	usernameBytes, err := os.ReadFile(cfg.UsernameFile)
	if err != nil {
		return "", "", fmt.Errorf("error reading username file %s: %v", cfg.UsernameFile, err)
	}
	username := strings.TrimSpace(string(usernameBytes))

	// Read password from file
	passwordBytes, err := os.ReadFile(cfg.PasswordFile)
	if err != nil {
		return "", "", fmt.Errorf("error reading password file %s: %v", cfg.PasswordFile, err)
	}
	password := strings.TrimSpace(string(passwordBytes))

	return username, password, nil
}

// getHTTPClient returns the HTTP client, optionally configuring TLS verification skip
func (c *infobloxDNSProviderSolver) getHTTPClient(cfg infobloxDNSProviderConfig) *http.Client {
	if cfg.SkipTLSVerify && c.httpClient.Transport == nil {
		// WARNING: InsecureSkipVerify disables TLS certificate validation
		// This creates a security vulnerability allowing man-in-the-middle attacks
		// Only use this for testing purposes with self-signed certificates
		log.Printf("WARNING: TLS certificate verification is disabled")
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return c.httpClient
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
func (c *infobloxDNSProviderSolver) getTXTRecords(cfg infobloxDNSProviderConfig, username, password, name string) ([]InfobloxTXTRecord, error) {
	client := c.getHTTPClient(cfg)
	// URL encode parameters to prevent injection attacks
	requestURL := fmt.Sprintf("https://%s/wapi/%s/record:txt?name=%s&view=%s",
		cfg.Host, cfg.Version, url.QueryEscape(name), url.QueryEscape(cfg.View))

	req, err := http.NewRequest("GET", requestURL, nil)
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
func (c *infobloxDNSProviderSolver) createTXTRecord(cfg infobloxDNSProviderConfig, username, password, name, text string) error {
	client := c.getHTTPClient(cfg)
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
func (c *infobloxDNSProviderSolver) deleteTXTRecord(cfg infobloxDNSProviderConfig, username, password, ref string) error {
	client := c.getHTTPClient(cfg)
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
