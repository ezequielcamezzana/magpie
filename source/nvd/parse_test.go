package nvd

import "testing"

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
	if err != nil {
		t.Fatalf("parseCVE: %v", err)
	}
	if c.ID != "CVE-2020-1" || c.Score != 9.8 || c.Severity != "CRITICAL" {
		t.Errorf("meta mismatch: %+v", c)
	}
	if len(c.Matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(c.Matches))
	}
	m := c.Matches[0]
	if m.Vendor != "lodash" || m.Product != "lodash" || m.TargetSw != "node.js" {
		t.Errorf("match slots: %+v", m)
	}
	if len(m.AffectedRanges) != 1 || m.AffectedRanges[0] != "[*, 4.17.21)" {
		t.Errorf("ranges = %v", m.AffectedRanges)
	}
	if len(m.FixedVersions) != 1 || m.FixedVersions[0] != "4.17.21" {
		t.Errorf("fixed = %v", m.FixedVersions)
	}
}
