// Package nvd is the HTTP client for the NVD CVE API (services.nvd.nist.gov).
// It only fetches the raw CVE JSON; parsing (CPE matches, metadata) lives in the
// magpie package so the same parser serves both fresh fetches and cached payloads.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
)

const (
	baseURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	userAgent = "Magpie/0.1.0"
	// retryBackoff is the wait between retries on a transient 5xx. Kept short
	// and independent of delay so a synchronous /collect isn't blocked for
	// delay*5 (= 30s without an API key) and time out.
	retryBackoff = 2 * time.Second
)

type Client struct {
	httpc  *http.Client
	apiKey string
	delay  time.Duration
}

func New(httpc *http.Client, apiKey string) *Client {
	if httpc == nil {
		httpc = http.DefaultClient
	}
	// WHY: NVD rate-limits ~50 req/30s with an API key, ~5 without.
	delay := 6 * time.Second
	if apiKey != "" {
		delay = 700 * time.Millisecond
	}
	return &Client{httpc: httpc, apiKey: apiKey, delay: delay}
}

// nvdPage is the envelope of the NVD CVE API: a list of CVE objects.
type nvdPage struct {
	Vulnerabilities []struct {
		CVE json.RawMessage `json:"cve"`
	} `json:"vulnerabilities"`
}

// QueryCPE fetches every CVE NVD knows for a CPE and returns the records that
// describe that exact CPE (vendor:product). Used by stage 4. The queried cpe is
// the short cpe:2.3:a:vendor:product form; NVD's virtualMatchString does the
// partial match.
func (c *Client) QueryCPE(ctx context.Context, cpe string) ([]collect.VulnRecord, error) {
	want := collect.ShortCPE(cpe)
	q := url.Values{}
	q.Set("virtualMatchString", want)

	var page nvdPage
	if err := c.fetch(ctx, baseURL+"?"+q.Encode(), &page); err != nil {
		return nil, err
	}

	var out []collect.VulnRecord
	for _, v := range page.Vulnerabilities {
		recs, err := ParseCVE(v.CVE)
		if err != nil {
			continue // skip a malformed CVE, don't fail the whole query
		}
		for _, r := range recs {
			// Keep only the record for the queried CPE; a CVE lists many.
			if collect.ShortCPE(r.MatchedOn) == want {
				out = append(out, r)
			}
		}
	}
	return out, nil
	// TODO: pagination — NVD caps at 2000 results/page; handle totalResults.
}

func (c *Client) fetch(ctx context.Context, rawURL string, out any) error {
	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, c.delay); err != nil {
				return err
			}
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

		// Per-request outcome (latency, status, transport failures like a hung
		// NVD connection) is logged uniformly by the health transport wrapping
		// c.httpc — see internal/server/health.
		resp, err := c.httpc.Do(req)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			// Rate limited: wait the configured spacing (or Retry-After).
			wait := c.delay * 5
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
			// Transient server error (NVD frequently 503s under load): short retry.
			if err := sleepCtx(ctx, retryBackoff); err != nil {
				return err
			}
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

// sleepCtx waits for d or until ctx is cancelled, returning ctx.Err() if the
// caller (e.g. a timed-out request) gave up first.
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
