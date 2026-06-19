package collect

import (
	"encoding/json"
	"errors"
	"time"
)

type Component struct {
	SPURL         string
	Name          string
	Description   string
	Licenses      []string
	LatestVersion string
	RepoURL       string
	Icon          string
	FetchedAt     time.Time
}

type Repository struct {
	URL         string
	Stars       int
	Forks       int
	Language    string
	LastPush    time.Time
	LastRelease time.Time
	FetchedAt   time.Time
}

type ResolvedCPE struct {
	SPURL       string // associated package (populated when reading from the DB)
	CPE         string
	CVE         string
	MatchedBy   []string // {name,vendor,ecosystem,range} — persisted as booleans
	Explanation string   // human-readable justification for the UI
	NVDVendor   string
	NVDProduct  string
	NVDTargetSw string
	NVDRanges   []string // every range NVD declares for the CPE (matching or not)
	OSVRanges   []string // our side of the cross-check (the CVE's OSV ranges)
	Ecosystem   string
	Names       []string // in-memory provenance (not persisted)
	Vendors     []string // in-memory provenance (not persisted)
}

type VulnRecord struct {
	Source             string
	QueryKey           string
	AffectedPackage    string // the affected component, always a purl
	MatchedOn          string // identifier matched: the purl (OSV/eco) or the CPE (NVD)
	OriginalID         string
	Aliases            []string
	CanonicalID        string
	Summary            string // OSV summary||details, NVD description, eco description
	Score              float64
	Severity           string
	AffectedVersions   []string
	AffectedRanges     []string
	FixedVersions      []string
	UnaffectedVersions []string
	Published          time.Time
	Modified           time.Time
	Payload            json.RawMessage
	FetchedAt          time.Time
}

type CanonicalGroup struct {
	CanonicalID string
	MaxScore    float64
	Records     []VulnRecord
}

// VulnGroup is a CanonicalGroup after running matching: each member carries
// its verdict (level 1) and the group carries the roll-up (level 2, DD §6).
type VulnGroup struct {
	CanonicalID string
	MaxScore    float64
	Affected    bool      // level 2 roll-up
	Summary     string    // best member summary, source priority nvd > osv > eco
	Created     time.Time // oldest Published among the members
	Updated     time.Time // newest Modified among the members
	Members     []VulnMember
}

type VulnMember struct {
	Record  VulnRecord
	Verdict MatchVerdict // level 1 per-record
}

type MatchVerdict struct {
	Matched  bool
	Reason   string
	Range    string
	NextFix  string
	Warnings []string
}

type SourceError struct {
	Source string
	Kind   string
	Err    error
}

// MarshalJSON serializes Err as a string ("message") — the error type is not
// JSON-serializable by itself.
func (e SourceError) MarshalJSON() ([]byte, error) {
	var msg string
	if e.Err != nil {
		msg = e.Err.Error()
	}
	return json.Marshal(struct {
		Source  string `json:"Source"`
		Kind    string `json:"Kind"`
		Message string `json:"Message"`
	}{e.Source, e.Kind, msg})
}

func (e *SourceError) UnmarshalJSON(b []byte) error {
	var v struct {
		Source  string
		Kind    string
		Message string
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	e.Source, e.Kind = v.Source, v.Kind
	if v.Message != "" {
		e.Err = errors.New(v.Message)
	}
	return nil
}

type Result struct {
	Coord      string
	Component  *Component
	Repository *Repository
	CPEs       []ResolvedCPE
	Groups     []VulnGroup
	Errors     []SourceError
}

const (
	SourceEcosystems = "ecosyste.ms"
	SourceOSV        = "osv"
	SourceCPER       = "cper"
	SourceNVD        = "nvd"
)

const (
	ReasonNoVersionSpecified       = "no_version_specified"
	ReasonUnsupportedVersionScheme = "unsupported_version_scheme"
	ReasonInUnaffectedList         = "in_unaffected_list"
	ReasonInFixedList              = "in_fixed_list"
	ReasonInAffectedList           = "in_affected_list"
	ReasonNotInAffectedList        = "not_in_affected_list"
	ReasonInAffectedRange          = "in_affected_range"
	ReasonNotInAffectedRange       = "not_in_affected_range"
	ReasonNoEvidence               = "no_evidence"
)
