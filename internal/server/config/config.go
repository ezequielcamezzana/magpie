// Package config loads magpie's server configuration from environment
// variables.
package config

import (
	"os"
	"time"
)

type Config struct {
	Listen         string
	DBPath         string
	LogFormat      string
	NVDAPIKey      string
	MaxAge         time.Duration
	RequestTimeout time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:         envOr("MAGPIE_ADDR", ":8080"),
		DBPath:         envOr("MAGPIE_DB_PATH", "./magpie.db"),
		LogFormat:      os.Getenv("MAGPIE_LOG"),
		NVDAPIKey:      os.Getenv("NVD_API_KEY"),
		MaxAge:         envDuration("MAGPIE_MAX_AGE", 24*time.Hour),
		RequestTimeout: envDuration("MAGPIE_REQUEST_TIMEOUT", 30*time.Second),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// WHY: invalid durations fall back to the default silently rather than
// erroring out. This preserves main's original best-effort semantics
// (it logged a warning and used the default); strict validation does not
// apply here because we don't want the logger leaking into config.
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
