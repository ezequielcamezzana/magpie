CREATE TABLE IF NOT EXISTS components (
	spurl          TEXT PRIMARY KEY,
	name           TEXT NOT NULL DEFAULT '',
	description    TEXT NOT NULL DEFAULT '',
	licenses_json  TEXT NOT NULL DEFAULT '[]',
	latest_version TEXT NOT NULL DEFAULT '',
	repo_url       TEXT NOT NULL DEFAULT '',
	icon           TEXT NOT NULL DEFAULT '',
	fetched_at     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS repositories (
	url          TEXT PRIMARY KEY,
	stars        INTEGER NOT NULL DEFAULT 0,
	forks        INTEGER NOT NULL DEFAULT 0,
	language     TEXT NOT NULL DEFAULT '',
	last_push    TEXT NOT NULL DEFAULT '',
	last_release TEXT NOT NULL DEFAULT '',
	fetched_at   TEXT NOT NULL DEFAULT ''
);

-- vulns: header de la vuln, deduplicado por (source, original_id). Los rangos
-- por paquete viven en package_vuln, no acá.
CREATE TABLE IF NOT EXISTS vulns (
	source       TEXT NOT NULL,
	original_id  TEXT NOT NULL,
	canonical_id TEXT,
	aliases      TEXT,
	-- summary: OSV summary||details, NVD description, eco description. El texto
	-- que el endpoint de vulns devuelve y la UI muestra.
	summary      TEXT NOT NULL DEFAULT '',
	score        REAL,
	severity     TEXT,
	published_at TEXT,
	modified_at  TEXT,
	payload      TEXT,
	fetched_at   TEXT NOT NULL,
	PRIMARY KEY (source, original_id)
);

CREATE INDEX IF NOT EXISTS idx_vulns_canonical ON vulns(canonical_id);
-- vulns PK is (source, original_id); a by-id read matches original_id alone
-- (OR canonical_id), so index original_id for the /vuln OR-lookup.
CREATE INDEX IF NOT EXISTS idx_vulns_original ON vulns(original_id);

-- package_vuln: impacto de una vuln sobre un paquete. query_key es la key de
-- cache/replacement (eco:name, spurl); affected_package es el purl real del
-- advisory.
CREATE TABLE IF NOT EXISTS package_vuln (
	source              TEXT NOT NULL,
	query_key           TEXT NOT NULL,
	-- affected_package: el componente afectado, SIEMPRE un purl.
	-- matched_on: el identificador con el que matcheamos — el purl (OSV/eco) o
	-- el CPE (NVD).
	affected_package    TEXT,
	matched_on          TEXT NOT NULL DEFAULT '',
	original_id         TEXT NOT NULL,
	affected_versions   TEXT,
	affected_ranges     TEXT,
	fixed_versions      TEXT,
	unaffected_versions TEXT,
	fetched_at          TEXT NOT NULL,
	PRIMARY KEY (source, query_key, original_id),
	FOREIGN KEY (source, original_id) REFERENCES vulns(source, original_id)
);

-- The PK is (source, query_key, original_id), so joins/FK lookups by
-- (source, original_id) — the vulns join and the /vuln by-id read — aren't
-- covered. SQLite doesn't auto-index FK child columns; index it explicitly.
CREATE INDEX IF NOT EXISTS idx_package_vuln_source_oid ON package_vuln(source, original_id);

-- cpes: un CPE resuelto por fila (no un blob JSON). Columnas escalares para que
-- el usuario pueda buscar por vendor/product/cpe además del spurl asociado; las
-- señales §3a como booleanos; explanation es la justificación human-readable
-- para la UI ("matched by name axios↔axios, …").
CREATE TABLE IF NOT EXISTS cpes (
	spurl             TEXT NOT NULL,
	cpe               TEXT NOT NULL,
	vendor            TEXT NOT NULL DEFAULT '',
	product           TEXT NOT NULL DEFAULT '',
	target_sw         TEXT NOT NULL DEFAULT '',
	cve               TEXT NOT NULL DEFAULT '',
	ecosystem         TEXT NOT NULL DEFAULT '',
	matched_name      INTEGER NOT NULL DEFAULT 0,
	matched_vendor    INTEGER NOT NULL DEFAULT 0,
	matched_ecosystem INTEGER NOT NULL DEFAULT 0,
	matched_range     INTEGER NOT NULL DEFAULT 0,
	-- ranges como JSON lists: nvd_ranges = todo lo que NVD declara para el CPE
	-- (matcheen o no); osv_ranges = nuestro lado del cruce. Permiten mostrar
	-- ambos cuando la señal range NO matcheó.
	nvd_ranges        TEXT NOT NULL DEFAULT '',
	osv_ranges        TEXT NOT NULL DEFAULT '',
	explanation       TEXT NOT NULL DEFAULT '',
	fetched_at        TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (spurl, cpe)
);

CREATE INDEX IF NOT EXISTS idx_cpes_vendor_product ON cpes(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpes_cpe ON cpes(cpe);

-- missed_cpes: negative cache de CPER. Un paquete cuya búsqueda no resolvió
-- ningún CPE se registra acá con fetched_at. Mientras el registro sea fresco
-- (< MaxAge) CPER no vuelve a pegarle a NVD; vencido, se reintenta. Evita
-- re-buscar en cada request los paquetes que (todavía) no tienen CPE.
CREATE TABLE IF NOT EXISTS missed_cpes (
	spurl      TEXT PRIMARY KEY,
	fetched_at TEXT NOT NULL
);
