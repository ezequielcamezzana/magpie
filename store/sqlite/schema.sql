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
	score        REAL,
	severity     TEXT,
	published_at TEXT,
	modified_at  TEXT,
	payload      TEXT,
	fetched_at   TEXT NOT NULL,
	PRIMARY KEY (source, original_id)
);

CREATE INDEX IF NOT EXISTS idx_vulns_canonical ON vulns(canonical_id);

-- package_vuln: impacto de una vuln sobre un paquete. query_key es la key de
-- cache/replacement (eco:name, spurl); affected_package es el purl real del
-- advisory.
CREATE TABLE IF NOT EXISTS package_vuln (
	source              TEXT NOT NULL,
	query_key           TEXT NOT NULL,
	affected_package    TEXT,
	original_id         TEXT NOT NULL,
	affected_versions   TEXT,
	affected_ranges     TEXT,
	fixed_versions      TEXT,
	unaffected_versions TEXT,
	fetched_at          TEXT NOT NULL,
	PRIMARY KEY (source, query_key, original_id),
	FOREIGN KEY (source, original_id) REFERENCES vulns(source, original_id)
);

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
