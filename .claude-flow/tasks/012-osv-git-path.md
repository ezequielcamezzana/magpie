# Task 012: source/osv — cablear el path OSV-GIT (KindGitHub)

## Descripción
El cliente OSV nunca consulta para repos: `Query` tiene
`case purl.KindGitHub: return nil, nil` (TODO task 023). OSV-GIT tiene data rica
de upstream (curl/curl → 335 vulns, CURL-CVE-* con alias CVE y range SEMVER).
Cablear la query GIT + el filtrado por repo. Es la fuente correcta para purls
`github` (código upstream). Detectado al investigar curl.

## Pasos
1. En `source/osv/types.go`, agregar `Repo string \`json:"repo,omitempty"\`` al
   `rawRange` (las entradas GIT traen el repo ahí, no en `package`).
2. En `source/osv/client.go`:
   - `Query` `case purl.KindGitHub:` → query GIT con body
     `{"package":{"ecosystem":"GIT","name":q.RepoURL}}` (reusar la mecánica HTTP
     de `query`, parametrizando el body).
   - Selección GIT-aware: una entrada `affected` matchea si alguno de sus
     `ranges` es `type=="GIT"` con `repo` == `q.RepoURL` (comparar con y sin
     sufijo `.git`). El `package` viene vacío en GIT, así que NO se filtra por
     nombre.
   - Del entry matcheado, armar el `VulnRecord` usando los ranges **SEMVER** y la
     lista `versions` (los ranges `GIT` de commits se siguen skipeando, como ya
     hace `convertRange`). `queryKey` = `OSVQuery.StoreKey()` (ya da el repoURL
     lowercased para KindGitHub).
3. El matcher para github es semver (`match.For` cae a semver para ecosystem
   "GIT") — confirmar que los records GIT matcheen bien una versión (tag) contra
   el range SEMVER.
4. Tests en `source/osv/client_test.go`: query GIT con `httptest` que devuelve un
   CURL-CVE-like (package vacío, range GIT con repo + range SEMVER) → produce un
   `VulnRecord` con `AffectedRanges` SEMVER y filtrado por repo correcto.

## Archivos afectados
- `source/osv/types.go` — campo `Repo` en `rawRange`
- `source/osv/client.go` — query + filtrado GIT para `KindGitHub`
- `source/osv/client_test.go` — caso GIT end-to-end (stub)

## Definition of done
- `Query(ctx, OSVQuery{Kind:KindGitHub, RepoURL:"https://github.com/curl/curl"})`
  contra un stub GIT retorna ≥1 `VulnRecord` con `AffectedRanges` SEMVER no vacío.
- Una entrada cuyo GIT range apunta a OTRO repo no se incluye.
- Smoke manual: `GET /collect?purl=pkg:github/curl/curl` devuelve `Groups` no
  vacío (OSV directo da 335 para ese repo).
- `go test ./source/osv/` verde.

## Depende de
- ninguna (pkg/purl ya deriva RepoURL para github purls; OSVQuery ya arma KindGitHub)

## Notas
Las entradas OSV-GIT traen `package:{}` vacío + un range SEMVER (versiones
upstream) + un range GIT (commits, se skipea) + lista `versions`. Por eso el
matching upstream es factible con semver. Referencia Holmes: `osv.go` `QueryByGit`
+ `matchGitRepo`/`stripDotGit` (filtra por repo con/sin `.git`).

NO incluye el fallback "paquete de lenguaje cuyo ecosyste.ms repo_url es el
upstream real → si OSV-ecosystem da 0, probar OSV-GIT" — eso va en una task
aparte (013) y tiene el caveat de que para conan el repo_url es el recipe-index
(inútil), así que solo sirve para ecosistemas cuyo repo_url sea el upstream real.
