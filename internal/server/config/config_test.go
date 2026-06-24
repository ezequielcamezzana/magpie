package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

// clearConfigEnv unsets every config env var for the test, so an ambient
// MAGPIE_* in the dev shell doesn't leak into the assertions. t.Setenv("") reads
// as unset by the config loaders (they treat empty as absent) and is restored
// after the test.
func clearConfigEnv(t *testing.T) {
	for _, key := range []string{
		"MAGPIE_ADDR", "MAGPIE_DB_PATH", "MAGPIE_LOG", "MAGPIE_LOG_LEVEL",
		"NVD_API_KEY", "VULNCHECK_API_KEY",
		"MAGPIE_REQUEST_TIMEOUT", "MAGPIE_SOURCE_BUDGET",
		"MAGPIE_UPDATER_ENABLED", "MAGPIE_UPDATER_INTERVAL",
		"MAGPIE_UPDATER_STALE_TIME", "MAGPIE_UPDATER_BATCH",
		"MAGPIE_MAX_AGE", "MAGPIE_MAX_AGE_COMPONENTS", "MAGPIE_MAX_AGE_VULNS",
		"MAGPIE_MAX_AGE_CPES", "MAGPIE_MAX_AGE_MISSED_CPE",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadMaxAge_Defaults(t *testing.T) {
	clearConfigEnv(t)
	assert.Equal(t, collect.DefaultMaxAge(), loadMaxAge())
}

func TestLoadUpdater_Defaults(t *testing.T) {
	clearConfigEnv(t)
	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.UpdaterEnabled, "updater is opt-in")
	assert.Equal(t, time.Minute, cfg.UpdaterInterval)
	assert.Equal(t, 12*time.Hour, cfg.UpdaterStaleTime)
	assert.Equal(t, 1, cfg.UpdaterBatch)
}

func TestLoadUpdater_FromEnv(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("MAGPIE_UPDATER_ENABLED", "true")
	t.Setenv("MAGPIE_UPDATER_INTERVAL", "5m")
	t.Setenv("MAGPIE_UPDATER_STALE_TIME", "24h")
	t.Setenv("MAGPIE_UPDATER_BATCH", "5")
	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.UpdaterEnabled)
	assert.Equal(t, 5*time.Minute, cfg.UpdaterInterval)
	assert.Equal(t, 24*time.Hour, cfg.UpdaterStaleTime)
	assert.Equal(t, 5, cfg.UpdaterBatch)
}

func TestLoadVulnCheckAPIKey_FromEnv(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("VULNCHECK_API_KEY", "vc-token")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "vc-token", cfg.VulnCheckAPIKey)
}

func TestLoadVulnCheckAPIKey_Unset(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("VULNCHECK_API_KEY", "")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.VulnCheckAPIKey)
}

func TestLoadMaxAge_GlobalFallback(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("MAGPIE_MAX_AGE", "1h")
	got := loadMaxAge()
	assert.Equal(t, collect.UniformMaxAge(time.Hour), got)
}

func TestLoadMaxAge_PerTypeOverridesGlobal(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("MAGPIE_MAX_AGE", "1h")        // global fallback
	t.Setenv("MAGPIE_MAX_AGE_VULNS", "30m") // wins for Vulns only
	got := loadMaxAge()

	assert.Equal(t, 30*time.Minute, got.Vulns)
	assert.Equal(t, time.Hour, got.Components, "unset type falls back to global")
	assert.Equal(t, time.Hour, got.CPEs)
	assert.Equal(t, time.Hour, got.MissedCPE)
}
