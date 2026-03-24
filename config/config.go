package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server ServerConfig `toml:"server"`
	Email  EmailConfig  `toml:"email"`
	Limits LimitsConfig `toml:"limits"`
	Auth   AuthConfig   `toml:"auth"`
}

type ServerConfig struct {
	Listen      string `toml:"listen"`
	CapsuleRoot string `toml:"capsules_root"`
	DBPath      string `toml:"db_path"`
	LogPath     string `toml:"log_path"`
	Domain      string `toml:"domain"`
}

type EmailConfig struct {
	SMTPHost     string `toml:"smtp_host"`
	SMTPPort     int    `toml:"smtp_port"`
	FromAddress  string `toml:"from_address"`
	SMTPUsername string `toml:"-"`
	SMTPPassword string `toml:"-"`
}

type LimitsConfig struct {
	MaxFileSizeBytes     int64 `toml:"max_file_size_bytes"`
	MaxTotalStorageBytes int64 `toml:"max_total_storage_bytes"`
	MaxFilesPerUser      int   `toml:"max_files_per_user"`
}

type AuthConfig struct {
	AdminSecret         string `toml:"-"`
	JWTSecret           string `toml:"jwt_secret"`
	SessionDurationDays int    `toml:"session_duration_days"`
	BcryptCost          int    `toml:"bcrypt_cost"`
}

func Load(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	// Credentials always come from environment
	cfg.Email.SMTPUsername = requireEnv("SMTP_USERNAME")
	cfg.Email.SMTPPassword = requireEnv("SMTP_PASSWORD")
	if v := os.Getenv("ADMIN_SECRET"); v != "" {
		cfg.Auth.AdminSecret = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}

	if cfg.Auth.BcryptCost == 0 {
		cfg.Auth.BcryptCost = 12
	}
	if cfg.Auth.SessionDurationDays == 0 {
		cfg.Auth.SessionDurationDays = 30
	}
	return &cfg, nil
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "warning: environment variable %s is not set\n", key)
	}
	return v
}
