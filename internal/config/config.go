package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	RemoteHost      string   `json:"remote_host"`
	RemotePort      int      `json:"remote_port"`
	RemoteUser      string   `json:"remote_user"`
	RemoteKeyPath   string   `json:"remote_key_path"`
	RemotePassword  string   `json:"remote_password,omitempty"`
	RemoteBasePath  string   `json:"remote_base_path"`
	SourceDirs      []string `json:"source_dirs"`
	ExcludePaths    []string `json:"exclude_paths,omitempty"`
	PassphraseFile  string   `json:"passphrase_file,omitempty"`
	Passphrase      string   `json:"passphrase,omitempty"`
	WebPort         int      `json:"web_port"`
	WebPasswordHash string   `json:"web_password_hash"`
	WebTLSCert      string   `json:"web_tls_cert,omitempty"`
	WebTLSKey       string   `json:"web_tls_key,omitempty"`
	DataDir         string   `json:"data_dir"`
	KeySalt         string   `json:"key_salt"` // base64-encoded Argon2id salt
	NtfyTopic       string   `json:"ntfy_topic,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.WebPort == 0 {
		cfg.WebPort = 8443
	}
	if cfg.RemotePort == 0 {
		cfg.RemotePort = 22
	}
	if cfg.RemoteBasePath == "" {
		cfg.RemoteBasePath = "/backup/coldcrypt"
	}
	return &cfg, nil
}

func Save(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// GetPassphrase returns the passphrase from config or passphrase file.
func (c *Config) GetPassphrase() (string, error) {
	if c.Passphrase != "" {
		return c.Passphrase, nil
	}
	if c.PassphraseFile != "" {
		data, err := os.ReadFile(c.PassphraseFile)
		if err != nil {
			return "", err
		}
		pp := string(data)
		// Trim trailing newline
		if len(pp) > 0 && pp[len(pp)-1] == '\n' {
			pp = pp[:len(pp)-1]
		}
		return pp, nil
	}
	return "", errors.New("no passphrase configured (set passphrase or passphrase_file in config)")
}

// DefaultConfigPath returns the default config file path within dataDir.
func DefaultConfigPath(dataDir string) string {
	return filepath.Join(dataDir, "config.json")
}
