package health

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSnapshotRules(t *testing.T) {
	tr := New()

	// No samples yet → unknown.
	assert.Equal(t, "unknown", tr.Snapshot()["nvd"].Status)

	// Fast 200s → ok.
	for i := 0; i < 3; i++ {
		tr.Record("osv", 200, 100*time.Millisecond)
	}
	osv := tr.Snapshot()["osv"]
	assert.Equal(t, "ok", osv.Status)
	assert.Equal(t, 3, osv.Samples)
	assert.Equal(t, int64(100), osv.AvgMs)

	// A 5xx anywhere in the window → bad.
	tr.Record("ecosyste.ms", 200, 100*time.Millisecond)
	tr.Record("ecosyste.ms", 503, 50*time.Millisecond)
	assert.Equal(t, "bad", tr.Snapshot()["ecosyste.ms"].Status)

	// All OK but slow average → slow.
	tr.Record("nvd", 200, 5*time.Second)
	assert.Equal(t, "slow", tr.Snapshot()["nvd"].Status)
}

func TestSourceForHost(t *testing.T) {
	assert.Equal(t, "nvd", sourceForHost("services.nvd.nist.gov"))
	assert.Equal(t, "osv", sourceForHost("api.osv.dev"))
	assert.Equal(t, "ecosyste.ms", sourceForHost("packages.ecosyste.ms"))
	assert.Equal(t, "vulncheck", sourceForHost("api.vulncheck.com"))
	assert.Equal(t, "", sourceForHost("example.com"))
}

func TestWindowDropsOldSamples(t *testing.T) {
	tr := New()
	tr.Record("nvd", 503, 10*time.Millisecond) // old bad sample
	for i := 0; i < window; i++ {
		tr.Record("nvd", 200, 10*time.Millisecond) // pushes the 503 out
	}
	assert.Equal(t, "ok", tr.Snapshot()["nvd"].Status, "503 should age out of the window")
}
