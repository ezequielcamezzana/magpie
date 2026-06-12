package magpie

import (
	"context"
	"time"
)

// StoreResult envuelve un valor cacheado con el momento en que fue obtenido.
//
// WHY: se llama StoreResult y no Result para no colisionar con el Result de
// dominio (result.go) en este mismo package; Go no permite dos identificadores
// con el mismo nombre aunque uno sea genérico.
//
// NOTE: Freshness vive en el caller — el Store solo expone FetchedAt; el
// caller compara contra MaxAge.
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
	Name      string // substring sobre name
	Ecosystem string // tipo de purl exacto (npm, pypi, …)
	Page      int
	Limit     int
}

type CPEQuery struct {
	Search string // substring sobre cpe/vendor/product/spurl (OR)
	Page   int
	Limit  int
}

// Store es la interfaz de persistencia del DD §7.
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
