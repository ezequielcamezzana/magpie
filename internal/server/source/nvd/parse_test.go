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
	  "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"vectorString":"x"}}]},
	  "configurations":[{"nodes":[{"cpeMatch":[
	    {"vulnerable":true,"criteria":"cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*","versionEndExcluding":"4.17.21"}
	  ]}]}]
	}`)
	c, err := parseCVE(raw)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2020-1", c.ID)
	assert.Equal(t, 9.8, c.Score)
	assert.Equal(t, "CRITICAL", c.Severity)
	require.Len(t, c.Matches, 1)
	m := c.Matches[0]
	assert.Equal(t, "lodash", m.Vendor)
	assert.Equal(t, "lodash", m.Product)
	assert.Equal(t, "node.js", m.TargetSw)
	assert.Equal(t, []string{"[*, 4.17.21)"}, m.AffectedRanges)
	assert.Equal(t, []string{"4.17.21"}, m.FixedVersions)
}
