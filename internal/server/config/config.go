// Package config loads magpie's server configuration from environment
// variables.
package config

import (
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

type Config struct {
	Listen          string
	DBPath          string
	LogFormat       string
	LogLevel        slog.Level
	NVDAPIKey       string
	VulnCheckAPIKey string
	MaxAge          collect.MaxAge
	RequestTimeout  time.Duration
	SourceBudget    time.Duration // per-source live-fetch bound; falls back to cache on timeout

	// Background passive updater: when enabled, every Interval it refreshes
	// the Batch oldest packages older than StaleTime, re-running the collect
	// pipeline without the cache. Opt-in (continuous outbound API calls).
	UpdaterEnabled   bool
	UpdaterInterval  time.Duration // how often a refresh cycle runs
	UpdaterStaleTime time.Duration // a package older than this is eligible
	UpdaterBatch     int           // packages refreshed per cycle
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:           envOr("MAGPIE_ADDR", ":8080"),
		DBPath:           envOr("MAGPIE_DB_PATH", "./magpie.db"),
		LogFormat:        os.Getenv("MAGPIE_LOG"),
		LogLevel:         envLogLevel("MAGPIE_LOG_LEVEL", slog.LevelInfo),
		NVDAPIKey:        os.Getenv("NVD_API_KEY"),
		VulnCheckAPIKey:  os.Getenv("VULNCHECK_API_KEY"),
		MaxAge:           loadMaxAge(),
		RequestTimeout:   envDuration("MAGPIE_REQUEST_TIMEOUT", 30*time.Second),
		SourceBudget:     envDuration("MAGPIE_SOURCE_BUDGET", 5*time.Second),
		UpdaterEnabled:   envBool("MAGPIE_UPDATER_ENABLED", false),
		UpdaterInterval:  envDuration("MAGPIE_UPDATER_INTERVAL", time.Minute),
		UpdaterStaleTime: envDuration("MAGPIE_UPDATER_STALE_TIME", 12*time.Hour),
		UpdaterBatch:     envInt("MAGPIE_UPDATER_BATCH", 1),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// loadMaxAge reads the per-type freshness windows. Each falls back to the
// global MAGPIE_MAX_AGE (when set), then to DefaultMaxAge.
func loadMaxAge() collect.MaxAge {
	def := collect.DefaultMaxAge()
	if global := envDuration("MAGPIE_MAX_AGE", 0); global > 0 {
		def = collect.UniformMaxAge(global)
	}
	return collect.MaxAge{
		Components: envDuration("MAGPIE_MAX_AGE_COMPONENTS", def.Components),
		Vulns:      envDuration("MAGPIE_MAX_AGE_VULNS", def.Vulns),
		CPEs:       envDuration("MAGPIE_MAX_AGE_CPES", def.CPEs),
		MissedCPE:  envDuration("MAGPIE_MAX_AGE_MISSED_CPE", def.MissedCPE),
	}
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

// envBool reads a boolean env var (1/t/true/0/f/false, case-insensitive),
// falling back to def when unset or unparseable.
func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// envLogLevel parses a slog level name (debug/info/warn/error,
// case-insensitive), falling back to def. Set MAGPIE_LOG_LEVEL=debug locally to
// see per-request NVD latency.
func envLogLevel(key string, def slog.Level) slog.Level {
	var lvl slog.Level
	if v := os.Getenv(key); v != "" {
		if err := lvl.UnmarshalText([]byte(v)); err == nil {
			return lvl
		}
	}
	return def
}

// envInt reads an integer env var, falling back to def when unset or
// unparseable.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
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
