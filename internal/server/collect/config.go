package collect

import (
	"net/http"
	"time"
)

// MaxAge holds the cache freshness window per data type (zero = always
// refetch). Components and the eco vulns fetched alongside them share one
// window (same ecosyste.ms fetch); Vulns governs OSV and NVD records.
type MaxAge struct {
	Components time.Duration
	Vulns      time.Duration
	CPEs       time.Duration
	MissedCPE  time.Duration
}

// DefaultMaxAge is the per-type freshness policy.
func DefaultMaxAge() MaxAge {
	return MaxAge{
		Components: 7 * 24 * time.Hour,
		Vulns:      12 * time.Hour,
		CPEs:       7 * 24 * time.Hour,
		MissedCPE:  24 * time.Hour,
	}
}

// UniformMaxAge sets every window to d (the global MAGPIE_MAX_AGE fallback).
func UniformMaxAge(d time.Duration) MaxAge {
	return MaxAge{Components: d, Vulns: d, CPEs: d, MissedCPE: d}
}

type Config struct {
	NVDAPIKey  string
	Store      Store
	HTTPClient *http.Client
	MaxAge     MaxAge

	// SourceBudget bounds how long each source's live fetch (ecosyste.ms, OSV,
	// CPER, NVD) may run. On timeout the stage falls back to whatever is cached
	// (even if stale) and yields a non-fatal warning, so collect stays fast.
	// 0 = no bound.
	SourceBudget time.Duration

	// EcosystemsFetcher and OSVFetcher are required; Collect errors if either
	// is nil (programming error, the entrypoint wires them).
	EcosystemsFetcher EcosystemsFetcher
	OSVFetcher        OSVFetcher
	// NVDFetcher is optional; nil skips CPE resolution (stage 3) and the
	// by-CPE NVD query (stage 4). Shared by both.
	NVDFetcher NVDFetcher
	// CVEFetcher resolves CVEs by id for CPER; nil disables stage 3 / CPER.
	CVEFetcher CVEFetcher
	// CPER is optional; nil skips stage 3.
	CPER CPERStage
}
