package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

func TestLoadMaxAge_Defaults(t *testing.T) {
	assert.Equal(t, collect.DefaultMaxAge(), loadMaxAge())
}

func TestLoadUpdater_Defaults(t *testing.T) {
	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.UpdaterEnabled, "updater is opt-in")
	assert.Equal(t, time.Minute, cfg.UpdaterInterval)
	assert.Equal(t, 12*time.Hour, cfg.UpdaterStaleTime)
	assert.Equal(t, 1, cfg.UpdaterBatch)
}

func TestLoadUpdater_FromEnv(t *testing.T) {
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
	t.Setenv("VULNCHECK_API_KEY", "vc-token")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "vc-token", cfg.VulnCheckAPIKey)
}

func TestLoadVulnCheckAPIKey_Unset(t *testing.T) {
	t.Setenv("VULNCHECK_API_KEY", "")
	cfg, err := Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.VulnCheckAPIKey)
}

func TestLoadMaxAge_GlobalFallback(t *testing.T) {
	t.Setenv("MAGPIE_MAX_AGE", "1h")
	got := loadMaxAge()
	assert.Equal(t, collect.UniformMaxAge(time.Hour), got)
}

func TestLoadMaxAge_PerTypeOverridesGlobal(t *testing.T) {
	t.Setenv("MAGPIE_MAX_AGE", "1h")        // global fallback
	t.Setenv("MAGPIE_MAX_AGE_VULNS", "30m") // wins for Vulns only
	got := loadMaxAge()

	assert.Equal(t, 30*time.Minute, got.Vulns)
	assert.Equal(t, time.Hour, got.Components, "unset type falls back to global")
	assert.Equal(t, time.Hour, got.CPEs)
	assert.Equal(t, time.Hour, got.MissedCPE)
}
