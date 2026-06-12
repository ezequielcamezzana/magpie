package osv

type rawVuln struct {
	ID               string        `json:"id"`
	Aliases          []string      `json:"aliases"`
	Upstream         []string      `json:"upstream"`
	Summary          string        `json:"summary"`
	Details          string        `json:"details"`
	Published        string        `json:"published"`
	Modified         string        `json:"modified"`
	Severity         []rawSeverity `json:"severity"`
	DatabaseSpecific rawDBSpecific `json:"database_specific"`
	Affected         []rawAffected `json:"affected"`
}

type rawSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type rawDBSpecific struct {
	Severity string `json:"severity"`
}

type rawAffected struct {
	Package  rawPackage `json:"package"`
	Versions []string   `json:"versions"`
	Ranges   []rawRange `json:"ranges"`
}

type rawPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

type rawRange struct {
	Type   string     `json:"type"`
	Repo   string     `json:"repo,omitempty"`
	Events []rawEvent `json:"events"`
}

type rawEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}
