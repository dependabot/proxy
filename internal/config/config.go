package config

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ProxyEnvSettings contains environment configuration for setting up the proxy.
type ProxyEnvSettings struct {
	APIEndpoint    string
	PackageManager string
	GroupedUpdate  string
	JobID          string
	JobToken       string
}

// Config is the structure of the proxy's config file
type Config struct {
	Credentials     Credentials          `json:"all_credentials"`
	CA              CaDetails            `json:"ca"`
	ProxyAuth       BasicAuthCredentials `json:"proxy_auth"`
	Experiments     Experiments          `json:"experiments"`
	EgressAllowlist EgressAllowlist      `json:"egress_allowlist"`
}

// EgressAllowlist controls domain-based egress filtering. Both flags default to
// false, which allows all traffic (fail-open). Observe logs non-allowlisted
// requests; Enforce blocks them with a 403.
type EgressAllowlist struct {
	Observe bool `json:"observe"`
	Enforce bool `json:"enforce"`
}

// Experiments contains job experiments passed to the proxy.
type Experiments map[string]any

// Enabled reports whether an experiment is explicitly enabled.
func (e Experiments) Enabled(name string) bool {
	enabled, ok := e[name].(bool)
	return ok && enabled
}

// Credential is a wrapper around map[string]any, which is the format
// of credential entries
type Credential map[string]any

// Type returns the credential's type
func (c Credential) Type() string {
	return c["type"].(string)
}

// GetString returns a string value or an empty string
func (c Credential) GetString(key string) string {
	if val, ok := c[key].(string); ok {
		return val
	}
	return ""
}

// Host returns the host of the credential, either from the "host" key or from the "url" key. Empty if neither is set.
func (c Credential) Host() string {
	if val, ok := c["host"].(string); ok {
		return strings.ToLower(val)
	}
	if val, ok := c["url"].(string); ok {
		u, err := url.Parse(val)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// GetListOfStrings returns an array of strings
func (c Credential) GetListOfStrings(key string) []string {
	value := c[key]
	switch val := value.(type) {
	case []string:
		return val
	case []any:
		strings := make([]string, len(val))
		for i, v := range val {
			if str, ok := v.(string); ok {
				strings[i] = str
			}
		}
		return strings
	}
	return nil
}

// Credentials is the format of credentials we get from the backend - an array
// of maps
type Credentials []Credential

// CaDetails includes the MITM CA certificate and private key
type CaDetails struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// BasicAuthCredentials represents credentials required for HTTP basic auth
type BasicAuthCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Parse parses a config file, returning a pointer to a Config struct
func Parse(path string) (_ *Config, err error) {
	var reader *os.File
	if path == "-" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(filepath.Clean(path))
		if err != nil {
			return nil, err
		}
		defer func() {
			err = errors.Join(err, reader.Close())
		}()
	}

	config := &Config{}
	if err := json.NewDecoder(reader).Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}
