// Package ecosystems is the HTTP client for the ecosyste.ms registry API.
// A single GET per SPURL returns package metadata, repository metadata and
// inline advisories, mapped into magpie's domain types.
package ecosystems

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

const (
	defaultBaseURL = "https://packages.ecosyste.ms/api/v1/registries/"
	userAgent      = "Magpie/0.1.0"
)

// ErrNotFound is returned for HTTP 404 (package unknown to ecosyste.ms).
var ErrNotFound = errors.New("ecosystems: package not found")

// registryByType maps a PURL type to its ecosyste.ms registry name. This table
// is ecosyste.ms-specific knowledge and lives here, not in pkg/purl.
var registryByType = map[string]string{
	"npm":      "npmjs.org",
	"pypi":     "pypi.org",
	"golang":   "proxy.golang.org",
	"cargo":    "crates.io",
	"gem":      "rubygems.org",
	"maven":    "repo1.maven.org",
	"nuget":    "nuget.org",
	"composer": "packagist.org",

	"conan":        "conan.io",
	"hex":          "hex.pm",
	"pub":          "pub.dev",
	"cran":         "cran.r-project.org",
	"hackage":      "hackage.haskell.org",
	"bioconductor": "bioconductor.org",
	"swift":        "swiftpackageindex.com",
	"cocoapods":    "cocoapods.org",
	"clojars":      "clojars.org",
	"julia":        "juliahub.com",
	"elm":          "package.elm-lang.org",
	"vcpkg":        "vcpkg.io",
}

type Client struct {
	httpc   *http.Client
	logger  *slog.Logger
	BaseURL string
}

func New(httpc *http.Client, logger *slog.Logger) *Client {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &Client{httpc: httpc, logger: logger, BaseURL: defaultBaseURL}
}

// WHY: collect.Collect cannot import this package (cycle), so we register
// the constructor as the real stage-1 fetcher.
func init() {
	collect.RegisterEcosystemsFetcher(func(httpc *http.Client, logger *slog.Logger) collect.EcosystemsFetcher {
		return New(httpc, logger)
	})
}

// Fetch retrieves package, repository and advisory data for a single SPURL.
func (c *Client) Fetch(ctx context.Context, spurl string) (collect.Component, *collect.Repository, []collect.VulnRecord, error) {
	p, err := purl.Parse(spurl)
	if err != nil {
		return collect.Component{}, nil, nil, err
	}
	id := purl.Decompose(p)

	registry := registryName(id)
	if registry == "" {
		// ecosyste.ms does not serve this type/release (rpm, fedora, distros
		// without a release-scoped registry…): not a failure, the pipeline
		// skips it and distro data arrives via OSV.
		return collect.Component{}, nil, nil, fmt.Errorf("%w: %s", collect.ErrSourceNotApplicable, id.Type)
	}

	canonical := purl.Strip(p)
	endpoint := c.BaseURL + url.PathEscape(registry) + "/packages/" + url.PathEscape(id.Name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return collect.Component{}, nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return collect.Component{}, nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return collect.Component{}, nil, nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return collect.Component{}, nil, nil, fmt.Errorf("ecosystems: unexpected status %d", resp.StatusCode)
	}

	var raw rawPackage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return collect.Component{}, nil, nil, err
	}

	// WHY: the client knows "this was fetched now"; the caller (collect)
	// compares FetchedAt against MaxAge.
	now := time.Now().UTC()

	comp := mapComponent(&raw, canonical, now)
	repo := mapRepository(&raw, now)
	vulns := mapAdvisories(raw.Advisories, canonical, id)

	return comp, repo, vulns, nil
}

func mapComponent(raw *rawPackage, spurl string, now time.Time) collect.Component {
	icon := raw.IconURL
	if icon == "" && raw.RepoMetadata != nil {
		icon = raw.RepoMetadata.IconURL
	}
	return collect.Component{
		SPURL:         spurl,
		Name:          raw.Name,
		Description:   raw.Description,
		Licenses:      raw.NormalizedLicenses,
		LatestVersion: raw.LatestReleaseNumber,
		RepoURL:       raw.RepositoryURL,
		Icon:          icon,
		FetchedAt:     now,
	}
}

func mapRepository(raw *rawPackage, now time.Time) *collect.Repository {
	rm := raw.RepoMetadata
	if rm == nil {
		return nil
	}
	repoURL := rm.HTMLURL
	if repoURL == "" {
		repoURL = raw.RepositoryURL
	}
	var lastPush, lastRelease time.Time
	if rm.PushedAt != "" {
		lastPush, _ = time.Parse(time.RFC3339, rm.PushedAt)
	}
	if raw.LatestReleasePublishedAt != "" {
		lastRelease, _ = time.Parse(time.RFC3339, raw.LatestReleasePublishedAt)
	}
	return &collect.Repository{
		URL:         repoURL,
		Stars:       rm.StargazersCount,
		Forks:       rm.ForksCount,
		Language:    rm.Language,
		LastPush:    lastPush,
		LastRelease: lastRelease,
		FetchedAt:   now,
	}
}

func mapAdvisories(raws []json.RawMessage, queryKey string, id purl.Identity) []collect.VulnRecord {
	out := make([]collect.VulnRecord, 0, len(raws))
	for _, payload := range raws {
		var adv rawAdvisory
		if err := json.Unmarshal(payload, &adv); err != nil {
			continue
		}
		out = append(out, mapAdvisory(&adv, payload, queryKey, id))
	}
	return out
}

func mapAdvisory(adv *rawAdvisory, payload json.RawMessage, queryKey string, id purl.Identity) collect.VulnRecord {
	var published, modified time.Time
	if adv.PublishedAt != "" {
		published, _ = time.Parse(time.RFC3339, adv.PublishedAt)
	}
	if adv.UpdatedAt != "" {
		modified, _ = time.Parse(time.RFC3339, adv.UpdatedAt)
	}

	rec := collect.VulnRecord{
		Source:     collect.SourceEcosystems,
		QueryKey:   queryKey,
		OriginalID: pickOriginalID(adv.Identifiers),
		Aliases:    adv.Identifiers,
		// WHY: canonical (CVE) derivation is Group's job; the client leaves
		// CanonicalID empty and collect stamps it before persisting.
		CanonicalID: "",
		Score:       adv.CVSSScore,
		// TODO: severity normalization is deferred; passed through as-is.
		Severity:  adv.Severity,
		Published: published,
		Modified:  modified,
		Payload:   payload,
	}

	pkg := pickAdvisoryPackage(adv.Packages, id)
	if pkg == nil {
		return rec
	}
	rec.AffectedPackage = pkg.PURL
	rec.AffectedVersions = pkg.AffectedVersions
	rec.UnaffectedVersions = pkg.UnaffectedVersions
	for _, ver := range pkg.Versions {
		if ver.VulnerableVersionRange != "" {
			rec.AffectedRanges = append(rec.AffectedRanges, parseEcosystemsRange(ver.VulnerableVersionRange)...)
		}
		if ver.FirstPatchedVersion != "" {
			rec.FixedVersions = append(rec.FixedVersions, ver.FirstPatchedVersion)
		}
	}
	return rec
}

// pickOriginalID prefers the native (non-CVE) advisory id over the CVE.
// WHY: the canonical CVE is derived separately (Group); OriginalID plus the
// canonical together must cover both GHSA and CVE so /vulnerabilities can find
// the record by either.
func pickOriginalID(identifiers []string) string {
	if len(identifiers) == 0 {
		return ""
	}
	for _, prefix := range []string{"GHSA-", "PYSEC-", "GSA-", "OSV-"} {
		for _, id := range identifiers {
			if strings.HasPrefix(id, prefix) {
				return id
			}
		}
	}
	return identifiers[0]
}

// pickAdvisoryPackage picks the package entry within an advisory matching the
// identity we asked about, falling back to the first entry.
func pickAdvisoryPackage(pkgs []rawAdvPackage, id purl.Identity) *rawAdvPackage {
	if len(pkgs) == 0 {
		return nil
	}
	if id.Name == "" {
		return &pkgs[0]
	}
	for i := range pkgs {
		p := &pkgs[i]
		if p.PackageName == id.Name && (id.Ecosystem == "" || strings.EqualFold(p.Ecosystem, id.Ecosystem)) {
			return p
		}
	}
	for i := range pkgs {
		if pkgs[i].PackageName == id.Name {
			return &pkgs[i]
		}
	}
	return &pkgs[0]
}

type rangeBound struct {
	op  string
	ver string
}

// parseEcosystemsRange converts an ecosyste.ms version range (e.g.
// ">= 1.0.0, < 1.2.6") to a Holmes interval string ("[1.0.0, 1.2.6)").
func parseEcosystemsRange(raw string) []string {
	parts := strings.Split(raw, ",")

	var lower, upper *rangeBound
	for _, part := range parts {
		b := parseBound(strings.TrimSpace(part))
		if b == nil {
			continue
		}
		if b.op == ">=" || b.op == ">" {
			lower = b
		} else {
			upper = b
		}
	}

	lv, lbracket := "*", "("
	if lower != nil {
		lv = lower.ver
		if lower.op == ">=" {
			lbracket = "["
		}
	}

	uv, ubracket := "*", ")"
	if upper != nil {
		uv = upper.ver
		if upper.op == "<=" || upper.op == "=" {
			ubracket = "]"
		}
	}

	if lv == "*" && uv == "*" {
		return nil
	}
	return []string{lbracket + lv + ", " + uv + ubracket}
}

func parseBound(part string) *rangeBound {
	for _, op := range []string{">=", "<=", ">", "<", "="} {
		if strings.HasPrefix(part, op) {
			return &rangeBound{op, strings.TrimSpace(part[len(op):])}
		}
	}
	return nil
}
