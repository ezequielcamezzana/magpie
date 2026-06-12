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
}
