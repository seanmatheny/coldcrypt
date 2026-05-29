package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is the merged runtime configuration used throughout the application.
// It is populated by loading config.json (UI-editable fields) and optionally
// secrets.json (infrastructure/puppet-managed fields) via LoadCombined.
type Config struct {
	// UI-editable fields — stored in config.json
	RemoteHost      string   `json:"remote_host"`
	RemotePort      int      `json:"remote_port"`
	RemoteUser      string   `json:"remote_user"`
	RemoteKeyPath   string   `json:"remote_key_path"`
	RemotePassword  string   `json:"remote_password,omitempty"`
	RemoteBasePath  string   `json:"remote_base_path"`
	SourceDirs      []string `json:"source_dirs"`
	ExcludePaths    []string `json:"exclude_paths,omitempty"`
	ExcludeRegexes  []string `json:"exclude_regexes,omitempty"`
	// Optional deleted-source retention. When enabled, files missing from the
	// source are retained for the configured value/unit before automatic purge.
	DeletedRetentionEnabled bool   `json:"deleted_retention_enabled,omitempty"`
	DeletedRetentionValue   int    `json:"deleted_retention_value,omitempty"`
	DeletedRetentionUnit    string `json:"deleted_retention_unit,omitempty"` // "days" or "weeks"

	// CompressionEnabled enables gzip compression of file content before
	// encryption. Existing uncompressed backups remain fully restorable;
	// the format is detected automatically at restore time.
	CompressionEnabled bool `json:"compression_enabled,omitempty"`

	// Infrastructure fields — stored in secrets.json (puppet-managed).
	// These fields are never read or written by the web UI.
	PassphraseFile  string `json:"passphrase_file,omitempty"`
	Passphrase      string `json:"passphrase,omitempty"`
	WebPort         int    `json:"web_port"`
	WebPasswordHash string `json:"web_password_hash"`
	WebTLSCert      string `json:"web_tls_cert,omitempty"`
	WebTLSKey       string `json:"web_tls_key,omitempty"`
	DataDir         string `json:"data_dir"`
	KeySalt         string `json:"key_salt"` // base64-encoded Argon2id salt
	NtfyTopic       string `json:"ntfy_topic,omitempty"`
}

// SecretsConfig holds infrastructure/puppet-managed fields that are stored in
// a separate file (secrets.json) and are never read or written by the web UI.
type SecretsConfig struct {
	PassphraseFile  string `json:"passphrase_file,omitempty"`
	Passphrase      string `json:"passphrase,omitempty"`
	WebPort         int    `json:"web_port,omitempty"`
	WebPasswordHash string `json:"web_password_hash,omitempty"`
	WebTLSCert      string `json:"web_tls_cert,omitempty"`
	WebTLSKey       string `json:"web_tls_key,omitempty"`
	DataDir         string `json:"data_dir,omitempty"`
	KeySalt         string `json:"key_salt,omitempty"`
	NtfyTopic       string `json:"ntfy_topic,omitempty"`
}

// Load reads and parses config.json. It applies default values for fields that
// are absent or zero. Infrastructure fields absent from this file will be zero
// until overridden by secrets.json via LoadCombined.
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
	if cfg.DeletedRetentionUnit == "" {
		cfg.DeletedRetentionUnit = "days"
	}
	return &cfg, nil
}

// LoadCombined loads config.json then applies any infrastructure fields found
// in secretsPath (secrets.json). Values in secrets.json take precedence over
// the same keys in config.json, enabling a clean split: config.json holds
// UI-editable settings, secrets.json holds puppet-managed infrastructure
// settings. If secretsPath does not exist the function succeeds silently,
// preserving backward compatibility with single-file configurations.
func LoadCombined(cfgPath, secretsPath string) (*Config, error) {
	cfg, err := Load(cfgPath)
	if err != nil {
		return nil, err
	}
	if secretsPath == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(secretsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// secrets.json not present — infra fields come from config.json (backward compat).
			return cfg, nil
		}
		return nil, fmt.Errorf("read secrets config %s: %w", secretsPath, err)
	}
	var sec SecretsConfig
	if err := json.Unmarshal(data, &sec); err != nil {
		return nil, fmt.Errorf("parse secrets config %s: %w", secretsPath, err)
	}
	applySecrets(cfg, &sec)
	return cfg, nil
}

// applySecrets overlays non-zero fields from sec onto cfg.
func applySecrets(cfg *Config, sec *SecretsConfig) {
	if sec.PassphraseFile != "" {
		cfg.PassphraseFile = sec.PassphraseFile
	}
	if sec.Passphrase != "" {
		cfg.Passphrase = sec.Passphrase
	}
	if sec.WebPort != 0 {
		cfg.WebPort = sec.WebPort
	}
	if sec.WebPasswordHash != "" {
		cfg.WebPasswordHash = sec.WebPasswordHash
	}
	if sec.WebTLSCert != "" {
		cfg.WebTLSCert = sec.WebTLSCert
	}
	if sec.WebTLSKey != "" {
		cfg.WebTLSKey = sec.WebTLSKey
	}
	if sec.DataDir != "" {
		cfg.DataDir = sec.DataDir
	}
	if sec.KeySalt != "" {
		cfg.KeySalt = sec.KeySalt
	}
	if sec.NtfyTopic != "" {
		cfg.NtfyTopic = sec.NtfyTopic
	}
}

// SaveUI writes only the UI-editable fields to path (config.json). Infrastructure
// fields (passphrase, key_salt, web_password_hash, etc.) are intentionally
// excluded so that puppet can manage secrets.json without risk of it being
// overwritten by web UI saves.
func SaveUI(cfg *Config, path string) error {
	type uiFields struct {
		RemoteHost              string   `json:"remote_host"`
		RemotePort              int      `json:"remote_port"`
		RemoteUser              string   `json:"remote_user"`
		RemoteKeyPath           string   `json:"remote_key_path"`
		RemotePassword          string   `json:"remote_password,omitempty"`
		RemoteBasePath          string   `json:"remote_base_path"`
		SourceDirs              []string `json:"source_dirs"`
		ExcludePaths            []string `json:"exclude_paths,omitempty"`
		ExcludeRegexes          []string `json:"exclude_regexes,omitempty"`
		DeletedRetentionEnabled bool     `json:"deleted_retention_enabled,omitempty"`
		DeletedRetentionValue   int      `json:"deleted_retention_value,omitempty"`
		DeletedRetentionUnit    string   `json:"deleted_retention_unit,omitempty"`
		CompressionEnabled      bool     `json:"compression_enabled,omitempty"`
	}
	ui := uiFields{
		RemoteHost:              cfg.RemoteHost,
		RemotePort:              cfg.RemotePort,
		RemoteUser:              cfg.RemoteUser,
		RemoteKeyPath:           cfg.RemoteKeyPath,
		RemotePassword:          cfg.RemotePassword,
		RemoteBasePath:          cfg.RemoteBasePath,
		SourceDirs:              cfg.SourceDirs,
		ExcludePaths:            cfg.ExcludePaths,
		ExcludeRegexes:          cfg.ExcludeRegexes,
		DeletedRetentionEnabled: cfg.DeletedRetentionEnabled,
		DeletedRetentionValue:   cfg.DeletedRetentionValue,
		DeletedRetentionUnit:    cfg.DeletedRetentionUnit,
		CompressionEnabled:      cfg.CompressionEnabled,
	}
	data, err := json.MarshalIndent(ui, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// SaveSecrets writes only the infrastructure fields to path (secrets.json).
func SaveSecrets(cfg *Config, path string) error {
	sec := SecretsConfig{
		PassphraseFile:  cfg.PassphraseFile,
		Passphrase:      cfg.Passphrase,
		WebPort:         cfg.WebPort,
		WebPasswordHash: cfg.WebPasswordHash,
		WebTLSCert:      cfg.WebTLSCert,
		WebTLSKey:       cfg.WebTLSKey,
		DataDir:         cfg.DataDir,
		KeySalt:         cfg.KeySalt,
		NtfyTopic:       cfg.NtfyTopic,
	}
	data, err := json.MarshalIndent(sec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// EnsureSecretsFile writes secrets.json only if it does not already exist.
// It is called before SaveUI to prevent infrastructure fields from being lost
// when migrating from a single-file config to the two-file layout.
func EnsureSecretsFile(cfg *Config, path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil // already exists
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat secrets config: %w", err)
	}
	return SaveSecrets(cfg, path)
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

// DefaultSecretsPath returns the default secrets file path given the config
// file path. By convention, secrets.json lives in the same directory as
// config.json.
func DefaultSecretsPath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "secrets.json")
}

// DeletedRetentionDuration returns the configured deleted-source retention
// duration when the feature is enabled and valid.
func (c *Config) DeletedRetentionDuration() (time.Duration, bool) {
	if !c.DeletedRetentionEnabled || c.DeletedRetentionValue <= 0 {
		return 0, false
	}
	switch strings.ToLower(c.DeletedRetentionUnit) {
	case "", "day", "days":
		return time.Duration(c.DeletedRetentionValue) * 24 * time.Hour, true
	case "week", "weeks":
		return time.Duration(c.DeletedRetentionValue) * 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}
