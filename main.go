package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
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
	ibClient ibclient.IBConnector
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

	// Get or create the Infoblox client
	err = c.getOrCreateClient(cfg)
	if err != nil {
		return fmt.Errorf("error initializing Infoblox client: %v", err)
	}

	// Extract the record name from the FQDN
	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	// Check if record already exists
	var existingRecords []ibclient.RecordTXT
	searchObj := ibclient.NewEmptyRecordTXT()

	queryParams := ibclient.NewQueryParams(
		false,
		map[string]string{
			"name": recordName,
			"view": cfg.View,
		},
	)

	err = c.ibClient.GetObject(searchObj, "", queryParams, &existingRecords)
	if err != nil {
		return fmt.Errorf("error checking existing records: %v", err)
	}

	// If a record with this exact value already exists, don't create a duplicate
	for _, record := range existingRecords {
		if record.Text != nil && *record.Text == ch.Key {
			log.Printf("TXT record already exists for %s with value %s", recordName, ch.Key)
			return nil
		}
	}

	// Extract zone from record name (everything after the first dot)
	zone := ""
	parts := strings.SplitN(recordName, ".", 2)
	if len(parts) > 1 {
		zone = parts[1]
	} else {
		zone = recordName
	}

	// Create TXT record object
	recordTXT := ibclient.NewRecordTXT(
		cfg.View,
		zone,
		recordName,
		ch.Key,
		uint32(cfg.TTL),
		true, // use TTL
		"",   // comment
		nil,  // extensible attributes
	)

	// Create the TXT record
	_, err = c.ibClient.CreateObject(recordTXT)
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

	// Get or create the Infoblox client
	err = c.getOrCreateClient(cfg)
	if err != nil {
		return fmt.Errorf("error initializing Infoblox client: %v", err)
	}

	// Extract the record name from the FQDN
	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	// Get existing records
	var existingRecords []ibclient.RecordTXT
	searchObj := ibclient.NewEmptyRecordTXT()

	queryParams := ibclient.NewQueryParams(
		false,
		map[string]string{
			"name": recordName,
			"view": cfg.View,
		},
	)

	err = c.ibClient.GetObject(searchObj, "", queryParams, &existingRecords)
	if err != nil {
		return fmt.Errorf("error getting existing records: %v", err)
	}

	// Delete only the record with the matching key
	for _, record := range existingRecords {
		if record.Text != nil && *record.Text == ch.Key {
			_, err = c.ibClient.DeleteObject(record.Ref)
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
	// Initialization will be done when we get the first request with config
	// The Infoblox client will be created on-demand with proper credentials
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

// getOrCreateClient gets or creates the Infoblox client with the given configuration
func (c *infobloxDNSProviderSolver) getOrCreateClient(cfg infobloxDNSProviderConfig) error {
	// If client already exists, reuse it
	if c.ibClient != nil {
		return nil
	}

	// Get credentials
	username, password, err := c.getCredentials(cfg)
	if err != nil {
		return fmt.Errorf("error getting credentials: %v", err)
	}

	// Create host config for Infoblox
	hostConfig := ibclient.HostConfig{
		Host:    cfg.Host,
		Version: cfg.Version,
		Port:    "443",
	}

	// Create transport config
	transportConfig := ibclient.NewTransportConfig(
		fmt.Sprintf("%t", cfg.SkipTLSVerify),
		20, // HTTP request timeout in seconds
		10, // HTTP pool connections
	)

	// Create auth config
	authConfig := ibclient.AuthConfig{
		Username: username,
		Password: password,
	}

	// Create the connector
	connector, err := ibclient.NewConnector(hostConfig, authConfig, transportConfig, nil, nil)
	if err != nil {
		return fmt.Errorf("error creating Infoblox connector: %v", err)
	}

	if cfg.SkipTLSVerify {
		log.Printf("WARNING: TLS certificate verification is disabled")
	}

	c.ibClient = connector
	return nil
}
