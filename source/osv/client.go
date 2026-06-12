// Package osv is the HTTP client for the OSV (api.osv.dev) vulnerability
// database. A single Query dispatches by purl.Kind; the Language and Linux
// paths share one HTTP query, mapping OSV vulns into VulnRecords.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	magpie "github.com/ezequielcamezzana/magpie"
	"github.com/ezequielcamezzana/magpie/pkg/purl"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

const (
	defaultBaseURL = "https://api.osv.dev/v1"
	userAgent      = "Magpie/0.1.0"
)

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

// WHY: magpie.Collect no puede importar este package (ciclo), así que registra
// su constructor como el fetcher real de stage 2.
func init() {
	magpie.RegisterOSVFetcher(func(httpc *http.Client, logger *slog.Logger) magpie.OSVFetcher {
		return New(httpc, logger)
	})
}

// Query looks up vulnerabilities for an OSV query. The strategy depends on
// q.Kind; Language and Linux share the same POST query, GitHub is pending.
func (c *Client) Query(ctx context.Context, q purl.OSVQuery) ([]magpie.VulnRecord, error) {
	switch q.Kind {
	case purl.KindLanguage:
		return c.query(ctx, q)
	case purl.KindLinux:
		return c.query(ctx, q)
	case purl.KindGitHub:
		return c.queryGit(ctx, q)
	}
	return nil, nil
}

func (c *Client) query(ctx context.Context, q purl.OSVQuery) ([]magpie.VulnRecord, error) {
	return c.queryBody(ctx, q, map[string]any{
		"package": map[string]string{"ecosystem": q.Ecosystem, "name": q.Name},
	})
}

// queryGit looks up vulns against the OSV GIT ecosystem, keyed by repo URL. The
// GIT path carries the repo in the affected ranges, so selection filters by repo
// instead of package name.
func (c *Client) queryGit(ctx context.Context, q purl.OSVQuery) ([]magpie.VulnRecord, error) {
	return c.queryBody(ctx, q, map[string]any{
		"package": map[string]string{"ecosystem": "GIT", "name": q.RepoURL},
	})
}

func (c *Client) queryBody(ctx context.Context, q purl.OSVQuery, body map[string]any) ([]magpie.VulnRecord, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/query", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: unexpected status %d", resp.StatusCode)
	}

	// COMPLEX: we keep each vuln's raw bytes for Payload, so decode into
	// json.RawMessage first and unmarshal each element separately.
	var envelope struct {
		Vulns         []json.RawMessage `json:"vulns"`
		NextPageToken string            `json:"next_page_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	// TODO: pagination — handle next_page_token if present.

	queryKey := queryKey(q)
	out := make([]magpie.VulnRecord, 0, len(envelope.Vulns))
	for _, payload := range envelope.Vulns {
		var v rawVuln
		if err := json.Unmarshal(payload, &v); err != nil {
			continue
		}
		// WHY: GIT results are keyed by repo, so a vuln whose ranges point at a
		// different repo isn't ours — drop it instead of emitting a record with
		// no ranges (which would falsely attribute the vuln to this repo).
		if q.Kind == purl.KindGitHub && pickAffected(v.Affected, q) == nil {
			continue
		}
		out = append(out, mapVuln(&v, payload, q, queryKey))
	}
	return out, nil
}

// queryKey is the per-source dedup key for the records, delegated to OSVQuery so
// collect and the client stay in sync (Language "<eco>:<name>", GitHub repoURL).
func queryKey(q purl.OSVQuery) string {
	return q.StoreKey()
}

// mergeUnique concatenates a and b, dropping empties and duplicates while
// preserving order.
func mergeUnique(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a)+len(b))
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range a {
		add(s)
	}
	for _, s := range b {
		add(s)
	}
	return out
}

func mapVuln(v *rawVuln, payload json.RawMessage, q purl.OSVQuery, queryKey string) magpie.VulnRecord {
	var published, modified time.Time
	if v.Published != "" {
		published, _ = time.Parse(time.RFC3339, v.Published)
	}
	if v.Modified != "" {
		modified, _ = time.Parse(time.RFC3339, v.Modified)
	}

	score := deriveScore(v.Severity)

	rec := magpie.VulnRecord{
		Source:     magpie.SourceOSV,
		QueryKey:   queryKey,
		OriginalID: v.ID,
		Aliases:    mergeUnique(v.Aliases, v.Upstream),
		// CanonicalID (CVE) derivation is Group's job; collect stamps it.
		CanonicalID: "",
		Score:       score,
		Severity:    deriveSeverity(v.DatabaseSpecific.Severity, score),
		Published:   published,
		Modified:    modified,
		Payload:     payload,
	}

	aff := pickAffected(v.Affected, q)
	if aff == nil {
		return rec
	}
	rec.AffectedPackage = aff.Package.Purl
	rec.AffectedVersions = aff.Versions
	for _, rng := range aff.Ranges {
		if rng.Type == "GIT" {
			continue
		}
		intervals, fixed := convertRange(rng)
		rec.AffectedRanges = append(rec.AffectedRanges, intervals...)
		rec.FixedVersions = append(rec.FixedVersions, fixed...)
	}
	return rec
}

// pickAffected selects the affected entry matching the queried package.
// WHY: Linux distros encode the release in the ecosystem (e.g.
// "Ubuntu:24.04:LTS"), so exact equality misses the right entry and the old
// affected[0] fallback would attribute another release's ranges. For Linux we
// match by base ecosystem prefix plus the release token (when present), and
// return nil on no match so the vuln keeps no AffectedRanges. Languages keep the
// exact-match + affected[0] fallback.
func pickAffected(affected []rawAffected, q purl.OSVQuery) *rawAffected {
	if len(affected) == 0 {
		return nil
	}
	if q.Kind == purl.KindGitHub {
		// GIT entries leave package empty; the repo lives in a GIT range.
		for i := range affected {
			for _, rng := range affected[i].Ranges {
				if rng.Type == "GIT" && matchGitRepo(rng.Repo, q.RepoURL) {
					return &affected[i]
				}
			}
		}
		return nil
	}
	for i := range affected {
		p := affected[i].Package
		if p.Name != q.Name {
			continue
		}
		if q.Kind == purl.KindLinux {
			if strings.HasPrefix(p.Ecosystem, q.BaseEcosystem) &&
				(q.ReleaseToken == "" || strings.Contains(p.Ecosystem, q.ReleaseToken)) {
				return &affected[i]
			}
			continue
		}
		if strings.EqualFold(p.Ecosystem, q.Ecosystem) {
			return &affected[i]
		}
	}
	if q.Kind == purl.KindLinux {
		return nil
	}
	return &affected[0]
}

// matchGitRepo compares two repo URLs ignoring a trailing ".git" on either side.
func matchGitRepo(a, b string) bool {
	return strings.TrimSuffix(a, ".git") == strings.TrimSuffix(b, ".git")
}

// convertRange turns one OSV range into Holmes intervals plus its fixed
// versions. introduced "0"/absent → unbounded "*"; fixed → exclusive ")";
// last_affected → inclusive "]".
func convertRange(rng rawRange) (intervals []string, fixed []string) {
	lower := "*"
	for _, ev := range rng.Events {
		switch {
		case ev.Introduced != "":
			if ev.Introduced == "0" {
				lower = "*"
			} else {
				lower = ev.Introduced
			}
		case ev.Fixed != "":
			intervals = append(intervals, "["+lower+", "+ev.Fixed+")")
			fixed = append(fixed, ev.Fixed)
			lower = "*"
		case ev.LastAffected != "":
			intervals = append(intervals, "["+lower+", "+ev.LastAffected+"]")
			lower = "*"
		}
	}
	// introduced with no matching fixed/last_affected → open upper bound.
	if lower != "*" || hasOnlyIntroduced(rng) {
		intervals = append(intervals, "["+lower+", *)")
	}
	return intervals, fixed
}

func hasOnlyIntroduced(rng rawRange) bool {
	for _, ev := range rng.Events {
		if ev.Fixed != "" || ev.LastAffected != "" {
			return false
		}
	}
	return len(rng.Events) > 0
}

// deriveScore parses the CVSS vector to its numeric base score.
// WHY: OSV stores the CVSS vector string, not a number; we parse it with
// go-cvss (3.0/3.1/4.0) to get the base score. No vector / unparseable → 0.
func deriveScore(sev []rawSeverity) float64 {
	for _, s := range sev {
		vec := s.Score
		switch {
		case strings.HasPrefix(vec, "CVSS:4.0"):
			if c, err := gocvss40.ParseVector(vec); err == nil {
				return c.Score()
			}
		case strings.HasPrefix(vec, "CVSS:3.1"):
			if c, err := gocvss31.ParseVector(vec); err == nil {
				return c.BaseScore()
			}
		case strings.HasPrefix(vec, "CVSS:3.0"):
			if c, err := gocvss30.ParseVector(vec); err == nil {
				return c.BaseScore()
			}
		}
	}
	return 0
}

// deriveSeverity prefers the database-provided label, falling back to a label
// derived from the numeric score (CVSS v3 buckets).
func deriveSeverity(dbSeverity string, score float64) string {
	if dbSeverity != "" {
		return dbSeverity
	}
	switch {
	case score == 0:
		return ""
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MODERATE"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
