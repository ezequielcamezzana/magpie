package magpie

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

// NVDCVE is the slice of an NVD CVE record that CPER consumes: metadata to
// persist as an nvd vuln record, plus the per-(vendor:product) CPE matches used
// to resolve the package's CPE.
type NVDCVE struct {
	ID        string
	Score     float64
	Severity  string
	Published time.Time
	Modified  time.Time
	Matches   []NVDCPEMatch
}

// NVDCPEMatch is one (vendor, product) CPE NVD declares vulnerable for a CVE,
// with the version intervals and target_sw it pins.
type NVDCPEMatch struct {
	PartialCPE     string // cpe:2.3:a:vendor:product
	Vendor         string
	Product        string
	TargetSw       string   // CPE part 10; "" or "*" when unset
	AffectedRanges []string // "[lo, hi)" intervals
	FixedVersions  []string
}

type ResolvedCPE struct {
	SPURL       string // paquete asociado (poblado al leer de la DB)
	CPE         string
	CVE         string
	MatchedBy   []string // {name,vendor,ecosystem,range} — persistido como booleanos
	Explanation string   // justificación human-readable para la UI
	NVDVendor   string
	NVDProduct  string
	NVDTargetSw string
	NVDRanges   []string // todos los ranges que NVD declara para el CPE (matcheen o no)
	OSVRanges   []string // nuestro lado del cruce (ranges OSV del CVE)
	Ecosystem   string
	Names       []string // provenance in-memory (no persistido)
	Vendors     []string // provenance in-memory (no persistido)
}

type VulnRecord struct {
	Source             string
	QueryKey           string
	AffectedPackage    string
	OriginalID         string
	Aliases            []string
	CanonicalID        string
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

// VulnGroup es un CanonicalGroup tras correr matching: cada member trae su
// verdict (nivel 1) y el grupo trae el roll-up (nivel 2, DD §6).
type VulnGroup struct {
	CanonicalID string
	MaxScore    float64
	Affected    bool      // roll-up nivel 2
	Created     time.Time // Published más viejo entre los members
	Updated     time.Time // Modified más nuevo entre los members
	Members     []VulnMember
}

type VulnMember struct {
	Record  VulnRecord
	Verdict MatchVerdict // nivel 1 per-record
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

// MarshalJSON serializa Err como string ("message") — el tipo error no es
// JSON-serializable por sí mismo.
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
