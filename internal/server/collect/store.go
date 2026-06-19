package collect

import (
	"context"
	"time"
)

// StoreResult wraps a cached value with the moment it was fetched.
//
// WHY: named StoreResult instead of Result to avoid colliding with the domain
// Result (result.go) in this same package; Go doesn't allow two identifiers
// with the same name even if one is generic.
//
// NOTE: Freshness lives in the caller — the Store only exposes FetchedAt; the
// caller compares against MaxAge.
type StoreResult[T any] struct {
	Value     T
	FetchedAt time.Time
	Found     bool
}

type VulnQuery struct {
	ID       string
	Fuzzy    bool   // match ID as a substring (LIKE) instead of exact
	Source   string // exact pv.source (ecosyste.ms / osv / nvd); "" = all
	Order    string // cvss | updated | created; "" = default (fetched_at)
	Collapse bool   // one row per (source, original_id), ignoring matched_on
	Page     int
	Limit    int
}

type ComponentQuery struct {
	Name      string // substring over name
	Ecosystem string // exact purl type (npm, pypi, …)
	Page      int
	Limit     int
}

type CPEQuery struct {
	Search string // substring over cpe/vendor/product/spurl (OR)
	Page   int
	Limit  int
}

// Metrics holds raw aggregate counts for the dashboard. The API derives the
// CPE-match and fresh percentages from these; the store stays count-only.
type Metrics struct {
	Components        int // total components
	Vulns             int // total vuln advisories
	CPEs              int // total resolved CPE rows
	ComponentsWithCPE int // distinct components that resolved at least one CPE
	MissedCPEs        int // components where CPE resolution was tried and failed
	StaleComponents   int // components fetched before the freshness cutoff
}

// Store is the persistence interface from DD §7.
type Store interface {
	GetComponent(ctx context.Context, spurl string) (StoreResult[Component], error)
	PutComponent(ctx context.Context, c Component) error

	// StaleComponents returns up to limit spurls whose fetched_at is before
	// olderThan, oldest first. Used by the background updater to pick which
	// packages to refresh next.
	StaleComponents(ctx context.Context, olderThan time.Time, limit int) ([]string, error)

	QueryComponents(ctx context.Context, q ComponentQuery) ([]Component, int, error)
	QueryCPEs(ctx context.Context, q CPEQuery) ([]ResolvedCPE, int, error)

	// Metrics returns aggregate counts; staleBefore is the freshness cutoff.
	Metrics(ctx context.Context, staleBefore time.Time) (Metrics, error)

	GetRepository(ctx context.Context, repoURL string) (StoreResult[Repository], error)
	PutRepository(ctx context.Context, r Repository) error

	GetCPEs(ctx context.Context, spurl string) (StoreResult[[]ResolvedCPE], error)
	PutCPEs(ctx context.Context, spurl string, cpes []ResolvedCPE) error

	// Negative cache for CPE resolution: GetMissedCPE.Found marks a package
	// whose last resolution found no CPE (FetchedAt = when), PutMissedCPE
	// records that miss, DeleteMissedCPE clears it once a CPE resolves.
	GetMissedCPE(ctx context.Context, spurl string) (StoreResult[bool], error)
	PutMissedCPE(ctx context.Context, spurl string) error
	DeleteMissedCPE(ctx context.Context, spurl string) error

	GetVulns(ctx context.Context, source, queryKey string) (StoreResult[[]VulnRecord], error)
	PutVulns(ctx context.Context, source, queryKey string, vs []VulnRecord) error

	QueryVulns(ctx context.Context, q VulnQuery) ([]VulnRecord, int, error)

	Close() error
}
