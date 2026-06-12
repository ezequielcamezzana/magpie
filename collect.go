package magpie

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/ezequielcamezzana/magpie/pkg/match"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"
)

// ErrSourceNotApplicable lo devuelve un fetcher cuando no tiene un path de datos
// para este purl type (p.ej. ecosyste.ms no tiene registry para deb/rpm). No es
// un fallo: el stage se saltea sin emitir SourceError.
var ErrSourceNotApplicable = errors.New("source not applicable for purl type")

// EcosystemsFetcher es la dependencia de stage 1; *ecosystems.Client la
// satisface. Existe para poder stubear en tests.
//
// WHY: exportada (no interna) porque source/ecosystems debe referenciarla al
// registrar su constructor desde otro package — ver RegisterEcosystemsFetcher.
type EcosystemsFetcher interface {
	Fetch(ctx context.Context, spurl string) (Component, *Repository, []VulnRecord, error)
}

// newEcosystemsFetcher construye el fetcher real de stage 1.
//
// WHY: source/ecosystems importa este package (devuelve Component/etc.), así
// que magpie no puede importarlo de vuelta sin un ciclo. El paquete ecosystems
// registra acá su constructor en su init().
var newEcosystemsFetcher func(httpc *http.Client, logger *slog.Logger) EcosystemsFetcher

// RegisterEcosystemsFetcher instala el constructor del fetcher real. La llama
// source/ecosystems en su init().
func RegisterEcosystemsFetcher(f func(httpc *http.Client, logger *slog.Logger) EcosystemsFetcher) {
	newEcosystemsFetcher = f
}

// OSVFetcher es la dependencia de stage 2; *osv.Client la satisface. Espejo de
// EcosystemsFetcher para poder stubear en tests y evitar el ciclo de imports.
type OSVFetcher interface {
	Query(ctx context.Context, q purl.OSVQuery) ([]VulnRecord, error)
}

var newOSVFetcher func(httpc *http.Client, logger *slog.Logger) OSVFetcher

// RegisterOSVFetcher instala el constructor del fetcher real de OSV. La llama
// source/osv en su init().
func RegisterOSVFetcher(f func(httpc *http.Client, logger *slog.Logger) OSVFetcher) {
	newOSVFetcher = f
}

// runCPERStage es el stage 3 (CPER) instalado por el package cper. Mismo
// patrón que los fetchers: cper importa magpie, así que magpie no puede
// importarlo de vuelta sin un ciclo. nil = CPER no cableado → se saltea.
var runCPERStage func(ctx context.Context, httpc *http.Client, cfg Config, id purl.Identity, spurl, repoURL string, records []VulnRecord, now time.Time)

// RegisterCPER instala el stage 3. Lo llama el package cper en su init().
func RegisterCPER(f func(ctx context.Context, httpc *http.Client, cfg Config, id purl.Identity, spurl, repoURL string, records []VulnRecord, now time.Time)) {
	runCPERStage = f
}

// Collect orquesta el pipeline de recolección para una coordinate: stage 1
// (ecosyste.ms), stage 2 (OSV), y luego ensamblado + matching + roll-up.
func Collect(ctx context.Context, coord string, cfg Config) (*Result, error) {
	if cfg.Store == nil {
		return nil, errors.New("collect: cfg.Store is nil")
	}
	if coord == "" {
		return nil, errors.New("collect: empty coord")
	}
	p, err := purl.Parse(coord)
	if err != nil {
		return nil, err
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if newEcosystemsFetcher == nil {
		return nil, errors.New("collect: ecosystems fetcher not registered (blank-import source/ecosystems)")
	}

	identity := purl.Decompose(p)
	spurl := purl.Strip(p)
	q := identity.OSVQuery()
	osvKey := q.StoreKey()
	now := time.Now().UTC()

	fetcher := newEcosystemsFetcher(httpClient, slog.Default())
	res, errs := collectStage1(ctx, fetcher, cfg.Store, spurl, cfg.MaxAge, now)

	errs = append(errs, runOSV(ctx, httpClient, cfg.Store, q, osvKey, spurl, cfg.MaxAge, now)...)

	// Ensamblado: leer del store unifica cache-hit y fresh-fetch.
	var allRecords []VulnRecord
	if r, _ := cfg.Store.GetVulns(ctx, SourceEcosystems, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if osvKey != "" {
		if r, _ := cfg.Store.GetVulns(ctx, SourceOSV, osvKey); r.Found {
			allRecords = append(allRecords, r.Value...)
		}
	}

	// Stage 3: CPER — resuelve CPE(s) desde los CVE de allRecords y persiste los
	// CVE NVD como vuln records (source=nvd, key=spurl).
	repoURL := ""
	if res.Component != nil {
		repoURL = res.Component.RepoURL
	}
	if runCPERStage != nil {
		runCPERStage(ctx, httpClient, cfg, identity, spurl, repoURL, allRecords, now)
	}

	// Los records NVD que dejó CPER se suman al paquete (3ra fuente del canonical).
	if r, _ := cfg.Store.GetVulns(ctx, SourceNVD, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if c, _ := cfg.Store.GetCPEs(ctx, spurl); c.Found {
		res.CPEs = c.Value
	}

	// Si el pipeline no produjo Component (ecosyste.ms no cubre este purl) pero
	// sí hay vulns, sintetizamos uno desde el purl parseado para que la UI tenga
	// nombre y repo. Sólo github trae RepoURL acá (vía Decompose).
	if res.Component == nil && len(allRecords) > 0 {
		comp := syntheticComponent(identity, spurl, now)
		_ = cfg.Store.PutComponent(ctx, comp)
		res.Component = &comp
	}

	res.Groups = matchGroups(Group(allRecords), identity, identity.Version)
	orderGroups(res.Groups)
	res.Coord = coord
	res.Errors = errs
	return res, nil
}

// syntheticComponent arma un Component mínimo desde el purl decompuesto, para
// purls con vulns que ecosyste.ms no cubre (p.ej. pkg:github/...). RepoURL ya
// viene seteado por Decompose para github; vacío para el resto.
func syntheticComponent(id purl.Identity, spurl string, now time.Time) Component {
	return Component{
		SPURL:     spurl,
		Name:      id.Name,
		RepoURL:   id.RepoURL,
		FetchedAt: now,
	}
}

// FromStore ensambla un Result para coord usando SOLO la cache (store), sin
// fetchers ni red. Lo usa la página de componente, que no debe re-scrapear.
// Si coord no trae versión, el matching marca todas las vulns como afectadas.
func FromStore(ctx context.Context, coord string, st Store) (*Result, error) {
	if st == nil {
		return nil, errors.New("fromstore: store is nil")
	}
	p, err := purl.Parse(coord)
	if err != nil {
		return nil, err
	}

	identity := purl.Decompose(p)
	spurl := purl.Strip(p)
	osvKey := identity.OSVQuery().StoreKey()

	res := &Result{Coord: coord}
	if c, _ := st.GetComponent(ctx, spurl); c.Found {
		comp := c.Value
		res.Component = &comp
		if comp.RepoURL != "" {
			if r, _ := st.GetRepository(ctx, comp.RepoURL); r.Found {
				rv := r.Value
				res.Repository = &rv
			}
		}
	}

	var allRecords []VulnRecord
	if r, _ := st.GetVulns(ctx, SourceEcosystems, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if osvKey != "" {
		if r, _ := st.GetVulns(ctx, SourceOSV, osvKey); r.Found {
			allRecords = append(allRecords, r.Value...)
		}
	}
	// NVD records + CPEs ya resueltos (store-only, sin red).
	if r, _ := st.GetVulns(ctx, SourceNVD, spurl); r.Found {
		allRecords = append(allRecords, r.Value...)
	}
	if c, _ := st.GetCPEs(ctx, spurl); c.Found {
		res.CPEs = c.Value
	}

	res.Groups = matchGroups(Group(allRecords), identity, identity.Version)
	orderGroups(res.Groups)
	return res, nil
}

// orderGroups ordena los grupos para que ganen los más peligrosos y más nuevos:
// MaxScore (CVSS) desc, y a igual score el de Updated más reciente primero.
func orderGroups(groups []VulnGroup) {
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].MaxScore != groups[j].MaxScore {
			return groups[i].MaxScore > groups[j].MaxScore
		}
		return groups[i].Updated.After(groups[j].Updated)
	})
}

// runOSV resuelve stage 2 (cache-aware, mismo patrón que stage 1). Devuelve
// SourceErrors no fatales; nunca aborta el pipeline.
func runOSV(ctx context.Context, httpc *http.Client, st Store, q purl.OSVQuery, osvKey string, spurl string, maxAge time.Duration, now time.Time) []SourceError {
	if osvKey == "" {
		return nil
	}
	if newOSVFetcher == nil {
		// TODO: distinguir "disabled" de "broke".
		return []SourceError{{Source: SourceOSV, Kind: "other", Err: errors.New("osv fetcher not registered")}}
	}

	if cached, _ := st.GetVulns(ctx, SourceOSV, osvKey); cached.Found && IsFresh(cached.FetchedAt, maxAge, now) {
		return nil
	}

	records, err := newOSVFetcher(httpc, slog.Default()).Query(ctx, q)
	if err != nil {
		return []SourceError{{Source: SourceOSV, Kind: "other", Err: fmt.Errorf("osv query: %w", err)}}
	}

	// WHY: stampear el canonical por-record antes de persistir deja poblada la
	// columna canonical_id del store (DD §7 la indexa para /vulnerabilities).
	// FetchedAt va acá (el client no lo conoce) y alimenta la freshness del cache.
	for i := range records {
		records[i].CanonicalID = CanonicalIDFor(records[i])
		records[i].FetchedAt = now
		// WHY: OSV-GIT (github/curl/curl) viene con package vacío → sin purl la
		// vuln no queda asociada al paquete por affected_package. Estampamos el
		// spurl consultado solo cuando OSV no reporta uno (preserva el real).
		if records[i].AffectedPackage == "" {
			records[i].AffectedPackage = spurl
		}
	}
	_ = st.PutVulns(ctx, SourceOSV, osvKey, records)
	return nil
}

// matchGroups corre matching per-record sobre cada CanonicalGroup y hace el
// roll-up binario por grupo.
func matchGroups(groups []CanonicalGroup, identity purl.Identity, version string) []VulnGroup {
	out := make([]VulnGroup, 0, len(groups))
	for _, g := range groups {
		vg := VulnGroup{CanonicalID: g.CanonicalID, MaxScore: g.MaxScore}
		for _, r := range g.Records {
			// Created = Published más viejo; Updated = Modified más nuevo.
			if !r.Published.IsZero() && (vg.Created.IsZero() || r.Published.Before(vg.Created)) {
				vg.Created = r.Published
			}
			if r.Modified.After(vg.Updated) {
				vg.Updated = r.Modified
			}

			ev := match.Evidence{
				AffectedVersions:   r.AffectedVersions,
				AffectedRanges:     r.AffectedRanges,
				FixedVersions:      r.FixedVersions,
				UnaffectedVersions: r.UnaffectedVersions,
			}
			mr := match.For(r.Source, identity.Ecosystem).Match(version, ev)
			vg.Members = append(vg.Members, VulnMember{
				Record: r,
				Verdict: MatchVerdict{
					Matched:  mr.Matched,
					Reason:   mr.Reason,
					Range:    mr.Range,
					NextFix:  mr.NextFix,
					Warnings: mr.Warnings,
				},
			})
			// WHY: roll-up OR (DD §6 nivel 2) — el grupo está afectado si ALGÚN
			// record matcheó.
			if mr.Matched {
				vg.Affected = true
			}
		}
		out = append(out, vg)
	}
	return out
}

// collectStage1 resuelve Component/Repository/Vulns desde ecosyste.ms, leyendo
// del store si el dato está fresco y fetcheando+persistiendo si no.
func collectStage1(ctx context.Context, fetcher EcosystemsFetcher, st Store, spurl string, maxAge time.Duration, now time.Time) (*Result, []SourceError) {
	var errs []SourceError

	cached, _ := st.GetComponent(ctx, spurl)
	if cached.Found && IsFresh(cached.FetchedAt, maxAge, now) {
		comp := cached.Value
		var repo *Repository
		if comp.RepoURL != "" {
			if r, _ := st.GetRepository(ctx, comp.RepoURL); r.Found {
				rv := r.Value
				repo = &rv
			}
		}
		return &Result{Component: &comp, Repository: repo}, errs
	}

	comp, repo, vulns, err := fetcher.Fetch(ctx, spurl)
	if errors.Is(err, ErrSourceNotApplicable) {
		// ecosyste.ms no cubre este purl type (deb/rpm/apk/…): no es un error,
		// la data de distro llega por OSV. Skip limpio, sin SourceError.
		return &Result{}, errs
	}
	if err != nil {
		// TODO: clasificar el error (Kind sigue siempre "other").
		errs = append(errs, SourceError{Source: SourceEcosystems, Kind: "other", Err: err})
		return &Result{}, errs
	}

	_ = st.PutComponent(ctx, comp)
	if repo != nil {
		_ = st.PutRepository(ctx, *repo)
	}
	// WHY: stampear el canonical por-record deja poblada la columna canonical_id
	// del store (DD §7). Group igual re-deriva al leer — idempotente.
	// FetchedAt va acá (el client no lo conoce) y alimenta la freshness del cache.
	for i := range vulns {
		vulns[i].CanonicalID = CanonicalIDFor(vulns[i])
		vulns[i].FetchedAt = now
	}
	_ = st.PutVulns(ctx, SourceEcosystems, spurl, vulns)

	return &Result{Component: &comp, Repository: repo}, errs
}

// IsFresh reporta si fetchedAt está dentro de maxAge respecto a now. Es la
// regla de freshness del pipeline (el Store solo guarda FetchedAt); exportada
// porque el package cper la comparte.
//
// WHY: maxAge<=0 significa "siempre refetch" (decisión de diseño), por eso
// retorna false en ese caso aunque el dato sea reciente.
func IsFresh(fetchedAt time.Time, maxAge time.Duration, now time.Time) bool {
	if maxAge <= 0 {
		return false
	}
	return now.Sub(fetchedAt) <= maxAge
}
