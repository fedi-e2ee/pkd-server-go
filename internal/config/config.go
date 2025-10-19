package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/fedi-e2ee/pkd-server-go/internal/crypto"
	"github.com/spf13/viper"
)

// Config holds the application's configuration.
type Config struct {
	Server           Server              `mapstructure:"server"`
	Database         Database            `mapstructure:"database"`
	SigSum           SigSum              `mapstructure:"sigsum"`
	Peers            map[string]Peer     `mapstructure:"peers"`
	CheckpointPolicy CheckpointPolicy    `mapstructure:"checkpoint_policy"`
	Test             Test                `mapstructure:"test"`
}

// Test holds configuration options for testing purposes.
type Test struct {
	AllowPrivateIPs bool `mapstructure:"allow_private_ips"`
}

// CheckpointPolicy holds the configuration for automated checkpointing.
type CheckpointPolicy struct {
	TargetDirectory string `mapstructure:"target_directory"`
	Interval        string `mapstructure:"interval"`
	MessageThreshold int    `mapstructure:"message_threshold"`
}

// Peer holds the configuration for a peer directory.
type Peer struct {
	PublicKey string `mapstructure:"public_key"`
}

// Server holds the configuration for the HTTP server.
type Server struct {
	Host          string `mapstructure:"host"`
	Port          int    `mapstructure:"port"`
	PrivateKey    string `mapstructure:"private_key"`
	HPKESecretKey string `mapstructure:"hpke_secret_key"`
	KeyFile       KeyFile `mapstructure:"key_file"`

	// Decoded keys, populated by LoadAndValidate()
	SigningKey     ed25519.PrivateKey `mapstructure:"-"`
	HPKEPublicKey  kem.PublicKey      `mapstructure:"-"`
	HPKEPrivateKey kem.PrivateKey     `mapstructure:"-"`
}

type KeyFile struct {
	Path        string `mapstructure:"path"`
	Password    string `mapstructure:"password"`
	Argon2idTime    uint32 `mapstructure:"argon2id_time"`
	Argon2idMemory  uint32 `mapstructure:"argon2id_memory"`
	Argon2idThreads uint8  `mapstructure:"argon2id_threads"`
}

// Database holds the configuration for the database connection.
type Database struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}

// SigSum holds the configuration for the SigSum client.
type SigSum struct {
	URL       string `mapstructure:"url"`
	PublicKey string `mapstructure:"public_key"`
}

// New returns a new Config instance with default values.
func New() *Config {
	return &Config{
		Server: Server{
			Host: "127.0.0.1",
			Port: 8080,
		},
		Database: Database{
			Driver: "postgres",
			DSN:    "postgresql://user:password@localhost:5432/pkd?sslmode=disable",
		},
		SigSum: SigSum{
			URL:       "http://localhost:8081",
			PublicKey: "",
		},
	}
}

// Load loads the configuration from a file and environment variables.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Set default values
	v.SetDefault("server.host", "127.0.0.1")
	v.SetDefault("server.port", 8080)
	v.SetDefault("database.dsn", "postgresql://user:password@localhost:5432/pkd?sslmode=disable")
	v.SetDefault("sigsum.url", "http://localhost:8081")

	// Load from config file
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/pkd-server-go")
		_ = v.ReadInConfig() // Ignore errors if config file is not found
	}

	// Load from environment variables
	v.SetEnvPrefix("PKD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Unmarshal the config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadAndValidate loads the configuration and then decodes and validates keys.
func LoadAndValidate(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}

	// If a key file is specified, load keys from it.
	if cfg.Server.KeyFile.Path != "" {
		keyViper := viper.New()
		keyViper.SetConfigFile(cfg.Server.KeyFile.Path)
		if err := keyViper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		cfg.Server.PrivateKey = keyViper.GetString("server.private_key")
		cfg.Server.HPKESecretKey = keyViper.GetString("server.hpke_secret_key")
	}

	// Decode the ed25519 private key
	if cfg.Server.PrivateKey == "" {
		return nil, fmt.Errorf("server.private_key is not set")
	}
	signingKey, err := crypto.DecodeSecretKey(cfg.Server.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server.private_key: %w", err)
	}
	cfg.Server.SigningKey = signingKey

	// Decode the HPKE secret key and derive the keypair
	if cfg.Server.HPKESecretKey == "" {
		return nil, fmt.Errorf("server.hpke_secret_key is not set")
	}
	hpkeSecretBytes, err := base64.RawURLEncoding.DecodeString(cfg.Server.HPKESecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server.hpke_secret_key: %w", err)
	}
	kemID := hpke.KEM_X25519_HKDF_SHA256
	hpkePk, hpkeSk := kemID.Scheme().DeriveKeyPair(hpkeSecretBytes)
	cfg.Server.HPKEPublicKey = hpkePk
	cfg.Server.HPKEPrivateKey = hpkeSk

	return cfg, nil
}
