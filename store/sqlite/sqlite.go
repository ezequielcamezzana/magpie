// Package sqlite implementa collect.Store sobre SQLite (driver puro Go
// modernc.org/sqlite) con el schema embebido en schema.sql.
package sqlite

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

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

var _ collect.Store = (*Store)(nil)

type Store struct {
	db *sql.DB
}

// Open abre la DB en dsn y ejecuta el schema. Ej: Open("magpie.db") o
// Open(":memory:") para una DB efímera en tests.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// WHY: con database/sql cada conexión :memory: ve una DB distinta y vacía;
	// limitar a una conexión hace que todo el pool comparta la misma DB.
	if isMemory(dsn) {
		db.SetMaxOpenConns(1)
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("exec schema: %w", err)
	}

	// Migraciones idempotentes: columnas agregadas después del schema inicial.
	// CREATE TABLE IF NOT EXISTS no altera tablas existentes, así que las DBs
	// viejas necesitan el ALTER; en DBs nuevas falla con "duplicate column" y
	// se ignora.
	for _, stmt := range []string{
		`ALTER TABLE cpes ADD COLUMN nvd_ranges TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cpes ADD COLUMN osv_ranges TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

const componentColumns = `spurl, name, description, licenses_json, latest_version, repo_url, icon, fetched_at`

// rowScanner abstrae *sql.Row y *sql.Rows para compartir scanComponent.
type rowScanner interface{ Scan(dest ...any) error }

// scanComponent reconstruye un Component desde la fila actual.
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

func (s *Store) QueryComponents(ctx context.Context, q collect.ComponentQuery) ([]collect.Component, int, error) {
	var conds []string
	var args []any
	if q.Name != "" {
		conds = append(conds, "name LIKE '%' || ? || '%'")
		args = append(args, q.Name)
	}
	if q.Ecosystem != "" {
		// WHY: el tipo de purl va entre "pkg:" y el primer "/" del spurl.
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
	// NOTE: nil y slice vacío se persisten ambos como "[]" y vuelven como
	// slice no-nil de largo 0.
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

// PutCPEs reemplaza el set de CPEs de spurl (una fila por CPE) en una tx,
// stampeando fetched_at = now.
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

// scanCPE reconstruye un ResolvedCPE (incluido SPURL) desde la fila actual y
// devuelve su fetched_at. El orden de columnas coincide con cpeColumns.
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

// QueryCPEs lista CPEs resueltos (read path para /cpes), buscables por
// cpe/vendor/product/spurl. Espejo de QueryComponents.
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

// vulnCols proyecta un VulnRecord desde el join package_vuln ⨝ vulns: header
// (aliases, score, severity, fechas, payload) desde vulns; impacto por paquete
// (query_key, affected_package, rangos) y la freshness de cache desde
// package_vuln. El orden debe coincidir con scanVuln.
const vulnCols = `pv.source, pv.query_key, pv.affected_package, pv.original_id,
	v.canonical_id, v.aliases, v.score, v.severity,
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
	// WHY: el caller refetchea todo el set por una key si cualquier fila está
	// stale, así que el FetchedAt del Result es el MIN de las filas. Se calcula
	// en Go (no MIN() SQL) porque sería un orden lexicográfico de strings que
	// timestamps con zonas distintas podrían romper.
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
	// WHY: DELETE + INSERTs en una sola tx para que el reemplazo del set sea
	// atómico; si un INSERT falla (p.ej. original_id duplicado viola la PK de
	// package_vuln), el rollback deja el set previo intacto.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// WHY: el reemplazo del set es por query (package_vuln); el header en vulns
	// se upsertea y se comparte entre queries, así que no se borra acá.
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

		// Header de la vuln: upsert, deduplicado por (source, original_id).
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO vulns (source, original_id, canonical_id, aliases, score, severity,
			                    published_at, modified_at, payload, fetched_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(source, original_id) DO UPDATE SET
			   canonical_id = excluded.canonical_id,
			   aliases = excluded.aliases,
			   score = excluded.score,
			   severity = excluded.severity,
			   published_at = excluded.published_at,
			   modified_at = excluded.modified_at,
			   payload = excluded.payload,
			   fetched_at = excluded.fetched_at`,
			source, v.OriginalID, v.CanonicalID, aliases, v.Score, v.Severity,
			formatTime(v.Published), formatTime(v.Modified),
			string(v.Payload), formatTime(v.FetchedAt)); err != nil {
			return fmt.Errorf("upsert vuln %q: %w", v.OriginalID, err)
		}

		// WARNING: INSERT normal (no OR REPLACE): un original_id duplicado en el
		// mismo set viola la PK de package_vuln y aborta la tx, no sobrescribe.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO package_vuln (source, query_key, affected_package, original_id,
			                           affected_versions, affected_ranges, fixed_versions,
			                           unaffected_versions, fetched_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			source, queryKey, v.AffectedPackage, v.OriginalID,
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
	where := ""
	var args []any
	if q.ID != "" {
		where = " WHERE v.original_id = ? OR v.canonical_id = ?"
		args = []any{q.ID, q.ID}
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*)`+vulnJoin+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count vulns: %w", err)
	}

	// NOTE: clamp mínimo defensivo; los defaults/máximos reales (p.ej. 100) los
	// aplica el handler.
	page := q.Page
	if page <= 0 {
		page = 1
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 25
	}
	offset := (page - 1) * limit

	// Orden determinístico para que la paginación sea estable.
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+vulnCols+vulnJoin+where+
			` ORDER BY pv.fetched_at DESC, pv.source, pv.query_key, pv.original_id LIMIT ? OFFSET ?`,
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

// scanVuln reconstruye un VulnRecord desde la fila actual y devuelve también su
// fetched_at parseado (para el cálculo de MIN en GetVulns).
func scanVuln(rows *sql.Rows) (collect.VulnRecord, time.Time, error) {
	var r collect.VulnRecord
	var aliases, affected, ranges, fixed, unaffected, payload string
	var publishedAt, modifiedAt, fetchedAt string
	if err := rows.Scan(
		&r.Source, &r.QueryKey, &r.AffectedPackage, &r.OriginalID,
		&r.CanonicalID, &aliases, &r.Score, &r.Severity,
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

// formatTime serializa a RFC3339Nano; el zero time se guarda como "".
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
