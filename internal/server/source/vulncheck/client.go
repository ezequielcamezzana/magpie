// Package vulncheck is the HTTP client for the VulnCheck NVD2 index
// (api.vulncheck.com/v3/index/nist-nvd2). It resolves a CVE by id; each result
// is an NVD2 CVE object, so parsing is delegated to nvd.ParseCVE.
package vulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/source/nvd"
)

const (
	baseURL   = "https://api.vulncheck.com/v3/index/nist-nvd2"
	userAgent = "Magpie/0.1.0"
	delay     = 2 * time.Second
	// retryBackoff is the wait between retries on a transient 5xx.
	retryBackoff = 2 * time.Second
)

type Client struct {
	httpc   *http.Client
	apiKey  string
	BaseURL string
}

func New(httpc *http.Client, apiKey string) *Client {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	return &Client{httpc: httpc, apiKey: apiKey, BaseURL: baseURL}
}

var _ collect.CVEFetcher = (*Client)(nil)

// vulncheckEnvelope is the response shape: a data array whose first element is
// the NVD2 CVE object.
type vulncheckEnvelope struct {
	Data []json.RawMessage `json:"data"`
}

// FetchCVE fetches one CVE by id and parses it into VulnRecords — one per
// application CPE the CVE declares. An empty result (HTTP 200, the CVE isn't in
// VulnCheck's NVD2 index — common for recent CVEs) returns no records and no
// error: it means "no NVD2 data for this CVE", not a fetch failure.
func (c *Client) FetchCVE(ctx context.Context, cveID string) ([]collect.VulnRecord, error) {
	q := url.Values{}
	q.Set("cve", cveID)

	var env vulncheckEnvelope
	if err := c.fetch(ctx, c.BaseURL+"?"+q.Encode(), &env); err != nil {
		return nil, err
	}
	if len(env.Data) == 0 {
		return nil, nil
	}
	return nvd.ParseCVE(env.Data[0])
}

func (c *Client) fetch(ctx context.Context, rawURL string, out any) error {
	const maxRetries = 3
	lastStatus := 0 // remembers the retried status (429/5xx) for the final error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, delay); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return fmt.Errorf("vulncheck: build request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		if c.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		}

		resp, err := c.httpc.Do(req)
		if err != nil {
			return &collect.HTTPError{Err: err}
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastStatus = resp.StatusCode

		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			wait := delay * 5
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if d, err2 := time.ParseDuration(ra + "s"); err2 == nil {
					wait = d
				}
			}
			if err := sleepCtx(ctx, wait); err != nil {
				return err
			}
			continue
		case resp.StatusCode >= 500:
			if err := sleepCtx(ctx, retryBackoff); err != nil {
				return err
			}
			continue
		case resp.StatusCode != http.StatusOK:
			return &collect.HTTPError{Status: resp.StatusCode}
		}
		if readErr != nil {
			return &collect.HTTPError{Err: fmt.Errorf("vulncheck: read body: %w", readErr)}
		}
		return json.Unmarshal(body, out)
	}
	return &collect.HTTPError{Status: lastStatus}
}

// sleepCtx waits for d or until ctx is cancelled, returning ctx.Err() if the
// caller gave up first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
