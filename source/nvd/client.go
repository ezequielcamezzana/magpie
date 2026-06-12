// Package nvd is the HTTP client for the NVD CVE API (services.nvd.nist.gov).
// It only fetches the raw CVE JSON; parsing (CPE matches, metadata) lives in the
// magpie package so the same parser serves both fresh fetches and cached payloads.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

const (
	baseURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	userAgent = "Magpie/0.1.0"
)

type Client struct {
	httpc  *http.Client
	logger *slog.Logger
	apiKey string
	delay  time.Duration
}

func New(httpc *http.Client, logger *slog.Logger, apiKey string) *Client {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	// WHY: NVD rate-limits ~50 req/30s con API key, ~5 sin key.
	delay := 6 * time.Second
	if apiKey != "" {
		delay = 700 * time.Millisecond
	}
	return &Client{httpc: httpc, logger: logger, apiKey: apiKey, delay: delay}
}

// FetchCVE trae una CVE de NVD y la parsea a *collect.NVDCVE (metadata + matches).
func (c *Client) FetchCVE(ctx context.Context, cveID string) (*collect.NVDCVE, error) {
	q := url.Values{}
	q.Set("cveId", cveID)

	var page struct {
		Vulnerabilities []struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := c.fetch(ctx, baseURL+"?"+q.Encode(), &page); err != nil {
		return nil, err
	}
	if len(page.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("nvd: %s not found", cveID)
	}
	return parseCVE(page.Vulnerabilities[0].CVE)
}

func (c *Client) fetch(ctx context.Context, rawURL string, out any) error {
	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(c.delay)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return fmt.Errorf("nvd: build request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}

		resp, err := c.httpc.Do(req)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			wait := c.delay * 5
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if d, err2 := time.ParseDuration(ra + "s"); err2 == nil {
					wait = d
				}
			}
			time.Sleep(wait)
			continue
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("nvd: unexpected status %d", resp.StatusCode)
		}
		if readErr != nil {
			return fmt.Errorf("nvd: read body: %w", readErr)
		}
		return json.Unmarshal(body, out)
	}
	return fmt.Errorf("nvd: max retries exceeded")
}
