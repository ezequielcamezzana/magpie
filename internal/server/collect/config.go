package collect

import (
	"net/http"
	"time"
)

type Config struct {
	NVDAPIKey  string
	Store      Store
	HTTPClient *http.Client
	MaxAge     time.Duration

	// EcosystemsFetcher and OSVFetcher are required; Collect errors if either
	// is nil (programming error, the entrypoint wires them).
	EcosystemsFetcher EcosystemsFetcher
	OSVFetcher        OSVFetcher
	// CPER is optional; nil skips stage 3.
	CPER CPERStage
}
