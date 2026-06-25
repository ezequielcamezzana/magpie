// Package db implements collect.Store on SQLite (pure Go driver
// modernc.org/sqlite) with the schema embedded from schema.sql.
package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "embed"

	"github.com/ezequielcamezzana/magpie/internal/server/collect"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

var _ collect.Store = (*Store)(nil)

type Store struct {
	db *sql.DB
}

// Open opens the DB at dsn and runs the schema. E.g. Open("magpie.db") or
// Open(":memory:") for an ephemeral DB in tests.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dataSource(dsn))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// WHY: with database/sql each :memory: connection sees a distinct, empty DB;
	// capping at one connection makes the whole pool share the same DB.
	if isMemory(dsn) {
		db.SetMaxOpenConns(1)
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("exec schema: %w", err)
	}

	// Idempotent migrations: columns added after the initial schema.
	// CREATE TABLE IF NOT EXISTS does not alter existing tables, so old DBs
	// need the ALTER; on fresh DBs it fails with "duplicate column" and is
	// ignored.
	for _, stmt := range []string{
		`ALTER TABLE cpes ADD COLUMN nvd_ranges TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cpes ADD COLUMN osv_ranges TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE vulns ADD COLUMN summary TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE package_vuln ADD COLUMN matched_on TEXT NOT NULL DEFAULT ''`,
		// Indexes for the vulns join / by-id read (idempotent on existing DBs).
		`CREATE INDEX IF NOT EXISTS idx_package_vuln_source_oid ON package_vuln(source, original_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_original ON vulns(original_id)`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}

	if err := foldLegacyKeys(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("fold legacy keys: %w", err)
	}

	return &Store{db: db}, nil
}

// foldLegacyKeys rewrites pre-fold storage keys to their normalized form.
// purl.Strip began case-folding namespace/name (cargo, npm, …) after some rows
// were already written, so the DB can hold a legacy pkg:cargo/Deno beside the
// canonical pkg:cargo/deno. Left alone the updater re-picks the un-normalized
// component forever and the UI lists duplicates. This collapses every legacy key
// into its canonical form across the spurl-keyed tables; the canonical row wins
// on conflict. Idempotent — once every key is normalized it's a no-op.
func foldLegacyKeys(db *sql.DB) error {
	ctx := context.Background()

	folds, err := legacyFolds(ctx, db)
	if err != nil {
		return fmt.Errorf("scan legacy keys: %w", err)
	}
	if len(folds) == 0 {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	for legacy, canonical := range folds {
		if err := foldKey(ctx, tx, legacy, canonical); err != nil {
			return fmt.Errorf("fold %q: %w", legacy, err)
		}
	}
	return tx.Commit()
}

// legacyFolds maps each stored key that isn't already normalized to its
// canonical form, scanning every table that keys by spurl. affected_package is
// deliberately not scanned: it can be an arbitrary advisory purl (possibly
// versioned), so we only re-point the exact legacy keys found in the key columns.
func legacyFolds(ctx context.Context, db *sql.DB) (map[string]string, error) {
	folds := map[string]string{}
	queries := []string{
		`SELECT spurl FROM components`,
		`SELECT DISTINCT spurl FROM cpes`,
		`SELECT spurl FROM missed_cpes`,
		`SELECT DISTINCT query_key FROM package_vuln WHERE source = ?`,
	}
	for _, q := range queries {
		rows, err := db.QueryContext(ctx, q, collect.SourceEcosystems)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				return nil, err
			}
			if c := canonicalSPURL(key); c != "" && c != key {
				folds[key] = c
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return folds, nil
}

// foldKey moves one legacy key to its canonical form across every table. Rows
// that would collide with an already-canonical row are dropped (the canonical
// row wins); the rest are renamed.
func foldKey(ctx context.Context, tx *sql.Tx, legacy, canonical string) error {
	steps := []struct{ drop, rename string }{
		// components / missed_cpes: the key alone is the PK.
		{`DELETE FROM components WHERE spurl = ? AND EXISTS (SELECT 1 FROM components WHERE spurl = ?)`,
			`UPDATE components SET spurl = ? WHERE spurl = ?`},
		{`DELETE FROM missed_cpes WHERE spurl = ? AND EXISTS (SELECT 1 FROM missed_cpes WHERE spurl = ?)`,
			`UPDATE missed_cpes SET spurl = ? WHERE spurl = ?`},
		// cpes: PK is (spurl, cpe) — collisions are per-cpe.
		{`DELETE FROM cpes WHERE spurl = ? AND cpe IN (SELECT cpe FROM cpes WHERE spurl = ?)`,
			`UPDATE cpes SET spurl = ? WHERE spurl = ?`},
		// package_vuln eco rows are keyed by the spurl (query_key); PK adds original_id.
		{`DELETE FROM package_vuln WHERE source = '` + collect.SourceEcosystems + `' AND query_key = ?
		  AND original_id IN (SELECT original_id FROM package_vuln WHERE source = '` + collect.SourceEcosystems + `' AND query_key = ?)`,
			`UPDATE package_vuln SET query_key = ? WHERE source = '` + collect.SourceEcosystems + `' AND query_key = ?`},
	}
	for _, s := range steps {
		if _, err := tx.ExecContext(ctx, s.drop, legacy, canonical); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.rename, canonical, legacy); err != nil {
			return err
		}
	}
	// affected_package is a plain column (no key): re-point exact legacy matches.
	if _, err := tx.ExecContext(ctx,
		`UPDATE package_vuln SET affected_package = ? WHERE affected_package = ?`, canonical, legacy); err != nil {
		return err
	}
	return nil
}

// canonicalSPURL returns the normalized storage key for a spurl, or "" if it
// can't be parsed. purl.Strip is idempotent, so an already-canonical key maps to
// itself.
func canonicalSPURL(spurl string) string {
	p, err := purl.Parse(spurl)
	if err != nil {
		return ""
	}
	return purl.Strip(p)
}

func (s *Store) Close() error {
	return s.db.Close()
}

const componentColumns = `spurl, name, description, licenses_json, latest_version, repo_url, icon, fetched_at`

// rowScanner abstracts *sql.Row and *sql.Rows so scanComponent can be shared.
type rowScanner interface{ Scan(dest ...any) error }

// scanComponent rebuilds a Component from the current row.
func scanComponent(sc rowScanner) (collect.Component, error) {
	var c collect.Component
	var licensesJSON, fetchedAt string
	if err := sc.Scan(&c.SPURL, &c.Name, &c.Description, &licensesJSON,
		&c.LatestVersion, &c.RepoURL, &c.Icon, &fetchedAt); err != nil {
		return collect.Component{}, err
	}
	if err := json.Unmarshal([]byte(licensesJSON), &c.Licenses); err != nil {
		return collect.Component{}, fmt.Errorf("unmarshal licenses: %w", err)
	}
	c.FetchedAt = parseTime(fetchedAt)
	return c, nil
}

func (s *Store) GetComponent(ctx context.Context, spurl string) (collect.StoreResult[collect.Component], error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+componentColumns+` FROM components WHERE spurl = ?`, spurl)

	c, err := scanComponent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return collect.StoreResult[collect.Component]{}, nil
	}
	if err != nil {
		return collect.StoreResult[collect.Component]{}, fmt.Errorf("scan component: %w", err)
	}

	return collect.StoreResult[collect.Component]{Value: c, FetchedAt: c.FetchedAt, Found: true}, nil
}

// NOTE: fetched_at is RFC3339Nano text, so this compares lexically. That is
// exact at second granularity; sub-second ordering noise is irrelevant for a
// staleness window measured in hours.
func (s *Store) StaleComponents(ctx context.Context, olderThan time.Time, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT spurl FROM components WHERE fetched_at < ? ORDER BY fetched_at ASC LIMIT ?`,
		formatTime(olderThan), limit)
	if err != nil {
		return nil, fmt.Errorf("stale components: %w", err)
	}
	defer rows.Close()

	var spurls []string
	for rows.Next() {
		var spurl string
		if err := rows.Scan(&spurl); err != nil {
			return nil, fmt.Errorf("scan stale component: %w", err)
		}
		spurls = append(spurls, spurl)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stale components: %w", err)
	}
	return spurls, nil
}

// Metrics runs one COUNT per field. staleBefore compares lexically against the
// RFC3339Nano fetched_at text — exact at second granularity, which is plenty
// for an hours-wide freshness window.
func (s *Store) Metrics(ctx context.Context, staleBefore time.Time) (collect.Metrics, error) {
	var m collect.Metrics
	counts := []struct {
		dst   *int
		query string
		arg   any
	}{
		{&m.Components, `SELECT COUNT(*) FROM components`, nil},
		// Distinct logical vulnerabilities affecting a package, matching the
		// /vulnerabilities list exactly: QueryVulns' collapse groups by the
		// canonical CVE (else original_id) and filters out the unattached per-CVE
		// cache (empty affected_package).
		{&m.Vulns, `SELECT COUNT(*) FROM (SELECT 1` + vulnJoin + ` WHERE pv.affected_package <> '' GROUP BY COALESCE(NULLIF(v.canonical_id, ''), pv.original_id))`, nil},
		{&m.CPEs, `SELECT COUNT(*) FROM cpes`, nil},
		{&m.ComponentsWithCPE, `SELECT COUNT(DISTINCT spurl) FROM cpes`, nil},
		{&m.MissedCPEs, `SELECT COUNT(*) FROM missed_cpes`, nil},
		{&m.StaleComponents, `SELECT COUNT(*) FROM components WHERE fetched_at < ?`, formatTime(staleBefore)},
	}
	for _, c := range counts {
		var err error
		if c.arg != nil {
			err = s.db.QueryRowContext(ctx, c.query, c.arg).Scan(c.dst)
		} else {
			err = s.db.QueryRowContext(ctx, c.query).Scan(c.dst)
		}
		if err != nil {
			return collect.Metrics{}, fmt.Errorf("metrics count: %w", err)
		}
	}
	return m, nil
}

func (s *Store) QueryComponents(ctx context.Context, q collect.ComponentQuery) ([]collect.Component, int, error) {
	var conds []string
	var args []any
	if q.Name != "" {
		conds = append(conds, "name LIKE '%' || ? || '%'")
		args = append(args, q.Name)
	}
	if q.Ecosystem != "" {
		// WHY: the purl type sits between "pkg:" and the first "/" of the spurl.
		conds = append(conds, "spurl LIKE 'pkg:' || ? || '/%'")
		args = append(args, q.Ecosystem)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM components`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count components: %w", err)
	}

	page := q.Page
	if page <= 0 {
		page = 1
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := (page - 1) * limit

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+componentColumns+` FROM components`+where+
			` ORDER BY name COLLATE NOCASE, spurl LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("query components: %w", err)
	}
	defer rows.Close()

	var out []collect.Component
	for rows.Next() {
		c, err := scanComponent(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan component: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate components: %w", err)
	}
	return out, total, nil
}

func (s *Store) PutComponent(ctx context.Context, c collect.Component) error {
	// NOTE: nil and empty slice are both persisted as "[]" and come back as a
	// non-nil slice of length 0.
	licenses := c.Licenses
	if licenses == nil {
		licenses = []string{}
	}
	licensesJSON, err := json.Marshal(licenses)
	if err != nil {
		return fmt.Errorf("marshal licenses: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO components (spurl, name, description, licenses_json, latest_version, repo_url, icon, fetched_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(spurl) DO UPDATE SET
		   name = excluded.name,
		   description = excluded.description,
		   licenses_json = excluded.licenses_json,
		   latest_version = excluded.latest_version,
		   repo_url = excluded.repo_url,
		   icon = excluded.icon,
		   fetched_at = excluded.fetched_at`,
		c.SPURL, c.Name, c.Description, string(licensesJSON),
		c.LatestVersion, c.RepoURL, c.Icon, formatTime(c.FetchedAt))
	if err != nil {
		return fmt.Errorf("put component: %w", err)
	}
	return nil
}

func (s *Store) GetRepository(ctx context.Context, repoURL string) (collect.StoreResult[collect.Repository], error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT url, stars, forks, language, last_push, last_release, fetched_at
		 FROM repositories WHERE url = ?`, repoURL)

	var r collect.Repository
	var lastPush, lastRelease, fetchedAt string
	err := row.Scan(&r.URL, &r.Stars, &r.Forks, &r.Language, &lastPush, &lastRelease, &fetchedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return collect.StoreResult[collect.Repository]{}, nil
	}
	if err != nil {
		return collect.StoreResult[collect.Repository]{}, fmt.Errorf("scan repository: %w", err)
	}

	r.LastPush = parseTime(lastPush)
	r.LastRelease = parseTime(lastRelease)
	r.FetchedAt = parseTime(fetchedAt)

	return collect.StoreResult[collect.Repository]{Value: r, FetchedAt: r.FetchedAt, Found: true}, nil
}

func (s *Store) PutRepository(ctx context.Context, r collect.Repository) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO repositories (url, stars, forks, language, last_push, last_release, fetched_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(url) DO UPDATE SET
		   stars = excluded.stars,
		   forks = excluded.forks,
		   language = excluded.language,
		   last_push = excluded.last_push,
		   last_release = excluded.last_release,
		   fetched_at = excluded.fetched_at`,
		r.URL, r.Stars, r.Forks, r.Language,
		formatTime(r.LastPush), formatTime(r.LastRelease), formatTime(r.FetchedAt))
	if err != nil {
		return fmt.Errorf("put repository: %w", err)
	}
	return nil
}

const cpeColumns = `spurl, cpe, vendor, product, target_sw, cve, ecosystem,
	matched_name, matched_vendor, matched_ecosystem, matched_range,
	nvd_ranges, osv_ranges, explanation, fetched_at`

func (s *Store) GetCPEs(ctx context.Context, spurl string) (collect.StoreResult[[]collect.ResolvedCPE], error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cpeColumns+` FROM cpes WHERE spurl = ? ORDER BY cpe`, spurl)
	if err != nil {
		return collect.StoreResult[[]collect.ResolvedCPE]{}, fmt.Errorf("query cpes: %w", err)
	}
	defer rows.Close()

	var out []collect.ResolvedCPE
	var fetchedAt time.Time
	for rows.Next() {
		c, ft, err := scanCPE(rows)
		if err != nil {
			return collect.StoreResult[[]collect.ResolvedCPE]{}, err
		}
		out = append(out, c)
		fetchedAt = ft
	}
	if err := rows.Err(); err != nil {
		return collect.StoreResult[[]collect.ResolvedCPE]{}, fmt.Errorf("iterate cpes: %w", err)
	}
	if len(out) == 0 {
		return collect.StoreResult[[]collect.ResolvedCPE]{}, nil
	}
	return collect.StoreResult[[]collect.ResolvedCPE]{Value: out, FetchedAt: fetchedAt, Found: true}, nil
}

// PutCPEs replaces the CPE set for spurl (one row per CPE) in a tx,
// stamping fetched_at = now.
func (s *Store) PutCPEs(ctx context.Context, spurl string, cpes []collect.ResolvedCPE) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM cpes WHERE spurl = ?`, spurl); err != nil {
		return fmt.Errorf("delete cpes: %w", err)
	}
	now := formatTime(time.Now().UTC())
	for _, c := range cpes {
		mb := map[string]bool{}
		for _, s := range c.MatchedBy {
			mb[s] = true
		}
		nvdRanges, err := marshalList(c.NVDRanges)
		if err != nil {
			return err
		}
		osvRanges, err := marshalList(c.OSVRanges)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO cpes (`+cpeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(spurl, cpe) DO UPDATE SET
			   vendor=excluded.vendor, product=excluded.product, target_sw=excluded.target_sw,
			   cve=excluded.cve, ecosystem=excluded.ecosystem,
			   matched_name=excluded.matched_name, matched_vendor=excluded.matched_vendor,
			   matched_ecosystem=excluded.matched_ecosystem, matched_range=excluded.matched_range,
			   nvd_ranges=excluded.nvd_ranges, osv_ranges=excluded.osv_ranges,
			   explanation=excluded.explanation, fetched_at=excluded.fetched_at`,
			spurl, c.CPE, c.NVDVendor, c.NVDProduct, c.NVDTargetSw, c.CVE, c.Ecosystem,
			boolToInt(mb["name"]), boolToInt(mb["vendor"]), boolToInt(mb["ecosystem"]), boolToInt(mb["range"]),
			nvdRanges, osvRanges, c.Explanation, now); err != nil {
			return fmt.Errorf("insert cpe %q: %w", c.CPE, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cpes: %w", err)
	}
	return nil
}

// GetMissedCPE returns the recorded "no CPE found" marker for spurl, if any.
func (s *Store) GetMissedCPE(ctx context.Context, spurl string) (collect.StoreResult[bool], error) {
	var fetched string
	err := s.db.QueryRowContext(ctx,
		`SELECT fetched_at FROM missed_cpes WHERE spurl = ?`, spurl).Scan(&fetched)
	if err == sql.ErrNoRows {
		return collect.StoreResult[bool]{}, nil
	}
	if err != nil {
		return collect.StoreResult[bool]{}, fmt.Errorf("query missed_cpes: %w", err)
	}
	return collect.StoreResult[bool]{Value: true, FetchedAt: parseTime(fetched), Found: true}, nil
}

// PutMissedCPE records that spurl resolved no CPE, stamping fetched_at = now.
func (s *Store) PutMissedCPE(ctx context.Context, spurl string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO missed_cpes (spurl, fetched_at) VALUES (?, ?)
		 ON CONFLICT(spurl) DO UPDATE SET fetched_at = excluded.fetched_at`,
		spurl, formatTime(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("put missed_cpes: %w", err)
	}
	return nil
}

// DeleteMissedCPE clears the miss marker for spurl (a CPE resolved).
func (s *Store) DeleteMissedCPE(ctx context.Context, spurl string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM missed_cpes WHERE spurl = ?`, spurl); err != nil {
		return fmt.Errorf("delete missed_cpes: %w", err)
	}
	return nil
}

// DeleteResult reports how many rows each delete removed.
type DeleteResult struct {
	Component int
	CPEs      int
	MissedCPE int
	EcoVulns  int
	OSVVulns  int
}

// DeleteComponent removes a package's package-specific cached rows: the
// component, its resolved CPEs, its negative-cache marker, and the ecosyste.ms +
// OSV vuln caches keyed to it (osvKey may be "" for types without an OSV query).
// WHY: shared caches — the per-CPE/per-CVE NVD records and the dedup'd `vulns`
// headers — are left intact, since other packages may still reference them.
// All deletes run in one transaction.
func (s *Store) DeleteComponent(ctx context.Context, spurl, osvKey string) (DeleteResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeleteResult{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var r DeleteResult
	del := func(dst *int, query string, args ...any) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		*dst = int(n)
		return nil
	}

	if err := del(&r.Component, `DELETE FROM components WHERE spurl = ?`, spurl); err != nil {
		return DeleteResult{}, fmt.Errorf("delete component: %w", err)
	}
	if err := del(&r.CPEs, `DELETE FROM cpes WHERE spurl = ?`, spurl); err != nil {
		return DeleteResult{}, fmt.Errorf("delete cpes: %w", err)
	}
	if err := del(&r.MissedCPE, `DELETE FROM missed_cpes WHERE spurl = ?`, spurl); err != nil {
		return DeleteResult{}, fmt.Errorf("delete missed_cpes: %w", err)
	}
	if err := del(&r.EcoVulns, `DELETE FROM package_vuln WHERE source = ? AND query_key = ?`, collect.SourceEcosystems, spurl); err != nil {
		return DeleteResult{}, fmt.Errorf("delete eco vulns: %w", err)
	}
	if osvKey != "" {
		if err := del(&r.OSVVulns, `DELETE FROM package_vuln WHERE source = ? AND query_key = ?`, collect.SourceOSV, osvKey); err != nil {
			return DeleteResult{}, fmt.Errorf("delete osv vulns: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return DeleteResult{}, fmt.Errorf("commit: %w", err)
	}
	return r, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func matchedByFromBools(mn, mv, me, mr string) []string {
	var out []string
	if mn == "1" {
		out = append(out, "name")
	}
	if mv == "1" {
		out = append(out, "vendor")
	}
	if me == "1" {
		out = append(out, "ecosystem")
	}
	if mr == "1" {
		out = append(out, "range")
	}
	return out
}

// scanCPE rebuilds a ResolvedCPE (including SPURL) from the current row and
// returns its fetched_at. Column order matches cpeColumns.
func scanCPE(sc rowScanner) (collect.ResolvedCPE, time.Time, error) {
	var c collect.ResolvedCPE
	var mn, mv, me, mr, nvdRanges, osvRanges, ft string
	if err := sc.Scan(&c.SPURL, &c.CPE, &c.NVDVendor, &c.NVDProduct, &c.NVDTargetSw,
		&c.CVE, &c.Ecosystem, &mn, &mv, &me, &mr, &nvdRanges, &osvRanges, &c.Explanation, &ft); err != nil {
		return collect.ResolvedCPE{}, time.Time{}, fmt.Errorf("scan cpe: %w", err)
	}
	c.MatchedBy = matchedByFromBools(mn, mv, me, mr)
	if err := unmarshalList(nvdRanges, &c.NVDRanges); err != nil {
		return collect.ResolvedCPE{}, time.Time{}, err
	}
	if err := unmarshalList(osvRanges, &c.OSVRanges); err != nil {
		return collect.ResolvedCPE{}, time.Time{}, err
	}
	return c, parseTime(ft), nil
}

// QueryCPEs lists resolved CPEs (read path for /cpes), searchable by
// cpe/vendor/product/spurl. Mirrors QueryComponents.
func (s *Store) QueryCPEs(ctx context.Context, q collect.CPEQuery) ([]collect.ResolvedCPE, int, error) {
	where := ""
	var args []any
	if q.Search != "" {
		where = ` WHERE cpe LIKE '%'||?||'%' OR vendor LIKE '%'||?||'%'
			OR product LIKE '%'||?||'%' OR spurl LIKE '%'||?||'%'`
		args = []any{q.Search, q.Search, q.Search, q.Search}
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cpes`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count cpes: %w", err)
	}

	page := q.Page
	if page <= 0 {
		page = 1
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := (page - 1) * limit

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cpeColumns+` FROM cpes`+where+
			` ORDER BY spurl, cpe LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("query cpes: %w", err)
	}
	defer rows.Close()

	var out []collect.ResolvedCPE
	for rows.Next() {
		c, _, err := scanCPE(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate cpes: %w", err)
	}
	return out, total, nil
}

// vulnCols projects a VulnRecord from the package_vuln ⨝ vulns join: header
// (aliases, score, severity, dates, payload) from vulns; per-package impact
// (query_key, affected_package, ranges) and cache freshness from
// package_vuln. Order must match scanVuln.
const vulnCols = `pv.source, pv.query_key, pv.affected_package, pv.matched_on, pv.original_id,
	v.canonical_id, v.aliases, v.summary, v.score, v.severity,
	pv.affected_versions, pv.affected_ranges, pv.fixed_versions, pv.unaffected_versions,
	v.published_at, v.modified_at, v.payload, pv.fetched_at`

const vulnJoin = ` FROM package_vuln pv
	JOIN vulns v ON pv.source = v.source AND pv.original_id = v.original_id`

func (s *Store) GetVulns(ctx context.Context, source, queryKey string) (collect.StoreResult[[]collect.VulnRecord], error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+vulnCols+vulnJoin+` WHERE pv.source = ? AND pv.query_key = ?`, source, queryKey)
	if err != nil {
		return collect.StoreResult[[]collect.VulnRecord]{}, fmt.Errorf("query vulns: %w", err)
	}
	defer rows.Close()

	var recs []collect.VulnRecord
	// WHY: the caller refetches the whole set for a key if any row is stale,
	// so the Result's FetchedAt is the MIN across rows. Computed in Go (not
	// SQL MIN()) because that would be a lexicographic string order that
	// timestamps with different zones could break.
	var minFetched time.Time
	for rows.Next() {
		r, fetched, err := scanVuln(rows)
		if err != nil {
			return collect.StoreResult[[]collect.VulnRecord]{}, err
		}
		if minFetched.IsZero() || fetched.Before(minFetched) {
			minFetched = fetched
		}
		recs = append(recs, r)
	}
	if err := rows.Err(); err != nil {
		return collect.StoreResult[[]collect.VulnRecord]{}, fmt.Errorf("iterate vulns: %w", err)
	}

	if len(recs) == 0 {
		return collect.StoreResult[[]collect.VulnRecord]{}, nil
	}
	return collect.StoreResult[[]collect.VulnRecord]{Value: recs, FetchedAt: minFetched, Found: true}, nil
}

func (s *Store) PutVulns(ctx context.Context, source, queryKey string, vs []collect.VulnRecord) error {
	// WHY: DELETE + INSERTs in a single tx so the set replacement is atomic;
	// if an INSERT fails (e.g. a duplicate original_id violates package_vuln's
	// PK), the rollback leaves the previous set intact.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// WHY: the set replacement is per query (package_vuln); the header in vulns
	// is upserted and shared across queries, so it is not deleted here.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM package_vuln WHERE source = ? AND query_key = ?`, source, queryKey); err != nil {
		return fmt.Errorf("delete package_vuln: %w", err)
	}

	for _, v := range vs {
		aliases, err := marshalList(v.Aliases)
		if err != nil {
			return err
		}
		affected, err := marshalList(v.AffectedVersions)
		if err != nil {
			return err
		}
		ranges, err := marshalList(v.AffectedRanges)
		if err != nil {
			return err
		}
		fixed, err := marshalList(v.FixedVersions)
		if err != nil {
			return err
		}
		unaffected, err := marshalList(v.UnaffectedVersions)
		if err != nil {
			return err
		}

		// Vuln header: upsert, deduplicated by (source, original_id).
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO vulns (source, original_id, canonical_id, aliases, summary, score, severity,
			                    published_at, modified_at, payload, fetched_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(source, original_id) DO UPDATE SET
			   canonical_id = excluded.canonical_id,
			   aliases = excluded.aliases,
			   summary = excluded.summary,
			   score = excluded.score,
			   severity = excluded.severity,
			   published_at = excluded.published_at,
			   modified_at = excluded.modified_at,
			   payload = excluded.payload,
			   fetched_at = excluded.fetched_at`,
			source, v.OriginalID, v.CanonicalID, aliases, v.Summary, v.Score, v.Severity,
			formatTime(v.Published), formatTime(v.Modified),
			string(v.Payload), formatTime(v.FetchedAt)); err != nil {
			return fmt.Errorf("upsert vuln %q: %w", v.OriginalID, err)
		}

		// matched_on defaults to the affected purl for OSV/eco (where the
		// component IS what we matched on); NVD sets it explicitly to the CPE.
		matchedOn := v.MatchedOn
		if matchedOn == "" {
			matchedOn = v.AffectedPackage
		}

		// WARNING: plain INSERT (no OR REPLACE): a duplicate original_id within
		// the same set violates package_vuln's PK and aborts the tx, it does
		// not overwrite.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO package_vuln (source, query_key, affected_package, matched_on, original_id,
			                           affected_versions, affected_ranges, fixed_versions,
			                           unaffected_versions, fetched_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			source, queryKey, v.AffectedPackage, matchedOn, v.OriginalID,
			affected, ranges, fixed, unaffected, formatTime(v.FetchedAt)); err != nil {
			return fmt.Errorf("insert package_vuln %q: %w", v.OriginalID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit vulns: %w", err)
	}
	return nil
}

func (s *Store) QueryVulns(ctx context.Context, q collect.VulnQuery) ([]collect.VulnRecord, int, error) {
	var conds []string
	var args []any
	if q.ID != "" {
		if q.Fuzzy {
			conds = append(conds, "(v.original_id LIKE ? OR v.canonical_id LIKE ?)")
			like := "%" + q.ID + "%"
			args = append(args, like, like)
		} else {
			conds = append(conds, "(v.original_id = ? OR v.canonical_id = ?)")
			args = append(args, q.ID, q.ID)
		}
	}
	if q.Source != "" {
		conds = append(conds, "pv.source = ?")
		args = append(args, q.Source)
	}
	if q.Collapse {
		// WHY: the collapsed list shows vulns affecting known packages. CPER's
		// raw per-CVE cache (query_key cve:…) lands in package_vuln with an empty
		// affected_package — package-independent records that only bloat the
		// scan/group. Real impacts (ecosyste.ms/OSV, NVD by-CPE) all stamp it, so
		// excluding the empty ones shrinks the working set without losing data.
		conds = append(conds, "pv.affected_package <> ''")
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	// WHY: the same (source, original_id, matched_on) can live under several
	// query_keys (the per-CVE and per-CPE NVD caches plus the package read
	// key), so the detail path collapses by that triple — a by-id lookup must
	// show each logical vuln-impact once. matched_on (the purl or CPE) is the
	// stable identifier; affected_package can vary (empty in the raw per-CVE
	// cache, the spurl in the package read). GROUP BY picks one row per group.
	//
	// The list (Collapse) groups by the logical vuln — its canonical CVE, else
	// its original_id — so each CVE shows once (its CVE/GHSA/PYSEC variants
	// collapse into one row titled by the canonical). With MAX(v.score), SQLite
	// pulls the other bare columns (score, dates, …) from the highest-severity
	// instance — the representative row.
	const advisoryKey = `COALESCE(NULLIF(v.canonical_id, ''), pv.original_id)`
	cols := vulnCols
	vulnGroupBy := ` GROUP BY pv.source, pv.original_id, pv.matched_on`
	if q.Collapse {
		vulnGroupBy = ` GROUP BY ` + advisoryKey
		cols = strings.Replace(cols, "v.score,", "MAX(v.score),", 1)
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM (SELECT 1`+vulnJoin+where+vulnGroupBy+`)`, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count vulns: %w", err)
	}

	// NOTE: defensive minimum clamp; the real defaults/maximums (e.g. 100) are
	// applied by the handler.
	page := q.Page
	if page <= 0 {
		page = 1
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := (page - 1) * limit

	// Deterministic order so pagination is stable. NULL scores/dates sort last
	// under DESC (SQLite ranks NULL lowest). Collapse mode orders by aggregates
	// (the group spans packages) and tiebreaks on the advisory key; the
	// non-collapsed path (detail) keeps its raw per-row order.
	orderBy := " ORDER BY pv.fetched_at DESC, pv.source, pv.query_key, pv.original_id"
	if q.Collapse {
		orderBy = " ORDER BY MAX(pv.fetched_at) DESC, " + advisoryKey
		switch q.Order {
		case "cvss":
			orderBy = " ORDER BY MAX(v.score) DESC, " + advisoryKey
		case "updated":
			orderBy = " ORDER BY MAX(v.modified_at) DESC, " + advisoryKey
		case "created":
			orderBy = " ORDER BY MAX(v.published_at) DESC, " + advisoryKey
		}
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cols+vulnJoin+where+vulnGroupBy+orderBy+` LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("query vulns: %w", err)
	}
	defer rows.Close()

	var recs []collect.VulnRecord
	for rows.Next() {
		r, _, err := scanVuln(rows)
		if err != nil {
			return nil, 0, err
		}
		recs = append(recs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate vulns: %w", err)
	}
	return recs, total, nil
}

// scanVuln rebuilds a VulnRecord from the current row and also returns its
// parsed fetched_at (for the MIN computation in GetVulns).
func scanVuln(rows *sql.Rows) (collect.VulnRecord, time.Time, error) {
	var r collect.VulnRecord
	var aliases, affected, ranges, fixed, unaffected, payload string
	var publishedAt, modifiedAt, fetchedAt string
	if err := rows.Scan(
		&r.Source, &r.QueryKey, &r.AffectedPackage, &r.MatchedOn, &r.OriginalID,
		&r.CanonicalID, &aliases, &r.Summary, &r.Score, &r.Severity,
		&affected, &ranges, &fixed, &unaffected,
		&publishedAt, &modifiedAt, &payload, &fetchedAt); err != nil {
		return collect.VulnRecord{}, time.Time{}, fmt.Errorf("scan vuln: %w", err)
	}

	if err := unmarshalList(aliases, &r.Aliases); err != nil {
		return collect.VulnRecord{}, time.Time{}, err
	}
	if err := unmarshalList(affected, &r.AffectedVersions); err != nil {
		return collect.VulnRecord{}, time.Time{}, err
	}
	if err := unmarshalList(ranges, &r.AffectedRanges); err != nil {
		return collect.VulnRecord{}, time.Time{}, err
	}
	if err := unmarshalList(fixed, &r.FixedVersions); err != nil {
		return collect.VulnRecord{}, time.Time{}, err
	}
	if err := unmarshalList(unaffected, &r.UnaffectedVersions); err != nil {
		return collect.VulnRecord{}, time.Time{}, err
	}
	if payload != "" {
		r.Payload = json.RawMessage(payload)
	}
	r.Published = parseTime(publishedAt)
	r.Modified = parseTime(modifiedAt)
	r.FetchedAt = parseTime(fetchedAt)

	return r, r.FetchedAt, nil
}

func marshalList[T any](xs []T) (string, error) {
	if xs == nil {
		return "", nil
	}
	b, err := json.Marshal(xs)
	if err != nil {
		return "", fmt.Errorf("marshal list: %w", err)
	}
	return string(b), nil
}

func unmarshalList[T any](s string, dst *[]T) error {
	// WHY: empty column → empty (non-nil) slice, matching the licenses
	// convention in PutComponent. The store never hands back nil lists.
	if s == "" {
		*dst = []T{}
		return nil
	}
	if err := json.Unmarshal([]byte(s), dst); err != nil {
		return fmt.Errorf("unmarshal list: %w", err)
	}
	return nil
}

// formatTime serializes to RFC3339Nano; the zero time is stored as "".
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func isMemory(dsn string) bool {
	return dsn == ":memory:" || strings.Contains(dsn, ":memory:") || strings.Contains(dsn, "mode=memory")
}

// dataSource adds WAL + a busy timeout to a file DSN. WHY: in the default
// rollback-journal mode with busy_timeout=0, the background updater's writes
// make a concurrent request's cache reads fail with SQLITE_BUSY — and the
// pipeline treats a read error as a cache miss, so it refetches from upstream
// (slow) even though the data is cached. WAL lets readers run alongside the
// writer; busy_timeout makes a contended write wait instead of erroring.
// In-memory DBs keep the bare DSN: one shared connection, no on-disk journal.
func dataSource(dsn string) string {
	if isMemory(dsn) {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
}
