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
	ID    string
	Page  int
	Limit int
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

// Store is the persistence interface from DD §7.
type Store interface {
	GetComponent(ctx context.Context, spurl string) (StoreResult[Component], error)
	PutComponent(ctx context.Context, c Component) error

	QueryComponents(ctx context.Context, q ComponentQuery) ([]Component, int, error)
	QueryCPEs(ctx context.Context, q CPEQuery) ([]ResolvedCPE, int, error)

	GetRepository(ctx context.Context, repoURL string) (StoreResult[Repository], error)
	PutRepository(ctx context.Context, r Repository) error

	GetCPEs(ctx context.Context, spurl string) (StoreResult[[]ResolvedCPE], error)
	PutCPEs(ctx context.Context, spurl string, cpes []ResolvedCPE) error

	GetVulns(ctx context.Context, source, queryKey string) (StoreResult[[]VulnRecord], error)
	PutVulns(ctx context.Context, source, queryKey string, vs []VulnRecord) error

	QueryVulns(ctx context.Context, q VulnQuery) ([]VulnRecord, int, error)

	Close() error
}
