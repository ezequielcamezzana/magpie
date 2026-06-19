package nvd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCVE(t *testing.T) {
	raw := []byte(`{
	  "id":"CVE-2020-1",
	  "published":"2020-01-02T00:00:00.000",
	  "descriptions":[{"lang":"es","value":"ignorame"},{"lang":"en","value":"Prototype pollution in lodash."}],
	  "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"vectorString":"x"}}]},
	  "configurations":[{"nodes":[{"cpeMatch":[
	    {"vulnerable":true,"criteria":"cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*","versionEndExcluding":"4.17.21"}
	  ]}]}]
	}`)
	recs, err := ParseCVE(raw)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	r := recs[0]
	assert.Equal(t, "CVE-2020-1", r.OriginalID)
	assert.Equal(t, "CVE-2020-1", r.CanonicalID)
	assert.Equal(t, "nvd", r.Source)
	assert.Equal(t, 9.8, r.Score)
	assert.Equal(t, "CRITICAL", r.Severity)
	assert.Equal(t, "Prototype pollution in lodash.", r.Summary)
	assert.Equal(t, "cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*", r.MatchedOn)
	assert.Empty(t, r.AffectedPackage, "component purl is filled by the caller, not the parser")
	assert.Equal(t, []string{"[*, 4.17.21)"}, r.AffectedRanges)
	assert.Equal(t, []string{"4.17.21"}, r.FixedVersions)
}
