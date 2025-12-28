package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	_ "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&infobloxDNSProviderSolver{},
	)
}

type infobloxDNSProviderSolver struct {
	ibClient ibclient.IBConnector
}

type infobloxDNSProviderConfig struct {
	// Host is the Infoblox WAPI host (e.g., ipam.illinois.edu or dev.ipam.illinois.edu)
	Host          string `json:"host"`
	Version       string `json:"version,omitempty"`
	View          string `json:"view,omitempty"`
	TTL           int    `json:"ttl,omitempty"`
	UsernameFile  string `json:"usernameFile,omitempty"`
	PasswordFile  string `json:"passwordFile,omitempty"`
	SkipTLSVerify bool   `json:"skipTLSVerify,omitempty"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
func (c *infobloxDNSProviderSolver) Name() string {
	return "infoblox"
}

func (c *infobloxDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {

	klog.Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Errorf("error loading config: %v", err)
		return fmt.Errorf("error loading config: %v", err)
	}

	err = c.getOrCreateClient(cfg)
	if err != nil {
		klog.Errorf("error initializing Infoblox client: %v", err)
		return fmt.Errorf("error initializing Infoblox client: %v", err)
	}

	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	var existingRecords []ibclient.RecordTXT
	searchObj := ibclient.NewEmptyRecordTXT()
	searchObj.Zone = "grad.illinois.edu"

	queryParams := ibclient.NewQueryParams(
		false,
		map[string]string{
			"name": recordName,
			"view": cfg.View,
		},
	)

	err = c.ibClient.GetObject(searchObj, "", queryParams, &existingRecords)
	// Error out if the error is not NotFoundError
	var notFoundErr *ibclient.NotFoundError
	if err != nil && !errors.As(err, &notFoundErr) {
		klog.Errorf("error getting existing records: %v", err)
		return fmt.Errorf("error checking existing records: %v", err)
	}

	for _, record := range existingRecords {
		if record.Text != nil && *record.Text == ch.Key {
			klog.Infof("TXT record already exists for %s with value %s", recordName, ch.Key)
			return nil
		}
	}

	recordTXT := ibclient.NewRecordTXT(
		cfg.View,
		"",
		recordName,
		ch.Key,
		uint32(cfg.TTL),
		true,
		"",
		nil,
	)

	_, err = c.ibClient.CreateObject(recordTXT)
	if err != nil {
		klog.Errorf("error creating TXT record: %v", err)
		return fmt.Errorf("error creating TXT record: %v", err)
	}

	klog.Infof("Successfully created TXT record for %s", recordName)
	return nil
}

func (c *infobloxDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Errorf("error loading config for CleanUp: %v", err)
		return fmt.Errorf("error loading config: %v", err)
	}

	err = c.getOrCreateClient(cfg)
	if err != nil {
		klog.Errorf("error initializing Infoblox client for CleanUp: %v", err)
		return fmt.Errorf("error initializing Infoblox client: %v", err)
	}

	recordName := strings.TrimSuffix(ch.ResolvedFQDN, ".")

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
	if err != nil && err.Error() != "not found" {
		klog.Errorf("error getting existing records for CleanUp: %v", err)
		return fmt.Errorf("error getting existing records: %v", err)
	}

	for _, record := range existingRecords {
		if record.Text != nil && *record.Text == ch.Key {
			_, err = c.ibClient.DeleteObject(record.Ref)
			if err != nil {
				klog.Errorf("error deleting TXT record: %v", err)
				return fmt.Errorf("error deleting TXT record: %v", err)
			}
			klog.Infof("Successfully deleted TXT record for %s", recordName)
			return nil
		}
	}

	klog.Infof("TXT record not found for %s with value %s, already cleaned up", recordName, ch.Key)
	return nil
}

func (c *infobloxDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	// The Infoblox client will be created on-demand with proper credentials
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (infobloxDNSProviderConfig, error) {
	// loadConfig is a small helper function that decodes JSON configuration into
	// the typed config struct.
	cfg := infobloxDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, fmt.Errorf("no configuration provided")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

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

	if cfg.Host == "" {
		return cfg, fmt.Errorf("host is required")
	}

	return cfg, nil
}

// getCredentials retrieves the username and password from mounted volume files
func (c *infobloxDNSProviderSolver) getCredentials(cfg infobloxDNSProviderConfig) (string, string, error) {
	usernameBytes, err := os.ReadFile(cfg.UsernameFile)
	if err != nil {
		return "", "", fmt.Errorf("error reading username file %s: %v", cfg.UsernameFile, err)
	}
	username := strings.TrimSpace(string(usernameBytes))

	passwordBytes, err := os.ReadFile(cfg.PasswordFile)
	if err != nil {
		return "", "", fmt.Errorf("error reading password file %s: %v", cfg.PasswordFile, err)
	}
	password := strings.TrimSpace(string(passwordBytes))

	return username, password, nil
}

func (c *infobloxDNSProviderSolver) getOrCreateClient(cfg infobloxDNSProviderConfig) error {
	if c.ibClient != nil {
		return nil
	}

	username, password, err := c.getCredentials(cfg)
	if err != nil {
		return fmt.Errorf("error getting credentials: %v", err)
	}

	klog.Infof("Found username %s", username)

	hostConfig := ibclient.HostConfig{
		Host:    cfg.Host,
		Version: cfg.Version,
		Port:    "443",
	}

	transportConfig := ibclient.NewTransportConfig(
		fmt.Sprintf("%t", cfg.SkipTLSVerify),
		20,
		2,
	)

	authConfig := ibclient.AuthConfig{
		Username: username,
		Password: password,
	}
	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}

	connector, err := ibclient.NewConnector(hostConfig, authConfig, transportConfig, requestBuilder, requestor)
	if err != nil {
		klog.Errorf("error creating Infoblox connector: %v", err)
		return fmt.Errorf("error creating Infoblox connector: %v", err)
	}

	if cfg.SkipTLSVerify {
		klog.Warning("Skipping TLS verification for Infoblox WAPI connection")
	}

	c.ibClient = connector
	return nil
}
