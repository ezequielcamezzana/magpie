package ecosystems

import "encoding/json"

// Internal shapes for the ecosyste.ms registry package endpoint. Only the
// fields we map are declared; the rest of the (large) response is ignored.

type rawPackage struct {
	Name                     string            `json:"name"`
	Description              string            `json:"description"`
	NormalizedLicenses       []string          `json:"normalized_licenses"`
	LatestReleaseNumber      string            `json:"latest_release_number"`
	LatestReleasePublishedAt string            `json:"latest_release_published_at"`
	RepositoryURL            string            `json:"repository_url"`
	IconURL                  string            `json:"icon_url"`
	RepoMetadata             *rawRepoMetadata  `json:"repo_metadata"`
	Advisories               []json.RawMessage `json:"advisories"`
}

type rawRepoMetadata struct {
	HTMLURL         string `json:"html_url"`
	FullName        string `json:"full_name"`
	Owner           string `json:"owner"`
	Language        string `json:"language"`
	StargazersCount int    `json:"stargazers_count"`
	ForksCount      int    `json:"forks_count"`
	PushedAt        string `json:"pushed_at"`
	IconURL         string `json:"icon_url"`
}

type rawAdvisory struct {
	Identifiers []string        `json:"identifiers"`
	Severity    string          `json:"severity"`
	CVSSScore   float64         `json:"cvss_score"`
	CVSSVector  string          `json:"cvss_vector"`
	PublishedAt string          `json:"published_at"`
	UpdatedAt   string          `json:"updated_at"`
	WithdrawnAt *string         `json:"withdrawn_at"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	SourceKind  string          `json:"source_kind"`
	References  []string        `json:"references"`
	Packages    []rawAdvPackage `json:"packages"`
}

type rawAdvPackage struct {
	PackageName        string          `json:"package_name"`
	PURL               string          `json:"purl"`
	Ecosystem          string          `json:"ecosystem"`
	Versions           []rawAdvVersion `json:"versions"`
	AffectedVersions   []string        `json:"affected_versions"`
	UnaffectedVersions []string        `json:"unaffected_versions"`
}

type rawAdvVersion struct {
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	FirstPatchedVersion    string `json:"first_patched_version"`
}
