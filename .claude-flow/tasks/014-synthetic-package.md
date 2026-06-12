# Task 014: synthetic package cuando hay vulns pero ecosyste.ms no da Component

## Descripción
Para purls que ecosyste.ms no cubre (p.ej. `pkg:github/curl/curl`) obtenemos
vulns (OSV-GIT, task 012) y CPEs, pero `Component == nil` → la UI no muestra
nombre ni repo. Solución: si tras el pipeline no hay Component **y** hay vulns,
sintetizar un Component desde el purl parseado y persistirlo. Para github, el
RepoURL ya lo deriva `Decompose`. Pedido del usuario.

## Pasos
1. En `collect.go`, después de ensamblar `allRecords` (ecosyste.ms + OSV + NVD) y
   antes de `matchGroups`, si `res.Component == nil && len(allRecords) > 0`:
   - Armar `Component{SPURL: spurl, Name: identity.Name, RepoURL: identity.RepoURL,
     FetchedAt: now}`. `identity.RepoURL` ya viene seteado por `Decompose` para
     github (`https://github.com/<ns>/<name>`); vacío para el resto (gitlab/otros
     hosts → task aparte).
   - `cfg.Store.PutComponent(ctx, comp)` y `res.Component = &comp`.
2. Helper `syntheticComponent(id purl.Identity, spurl string, now time.Time) Component`
   para mantener `Collect` legible.
3. No tocar el caso con Component real (solo cuando es `nil`). No sintetizar si no
   hay vulns (Component queda `nil`).

## Archivos afectados
- `collect.go` — síntesis + persist cuando `Component==nil && vulns>0`
- `collect_test.go` — casos (github con vulns, sin vulns, con Component real)

## Definition of done
- `Collect("pkg:github/curl/curl")` con OSV devolviendo vulns y ecosyste.ms
  `ErrSourceNotApplicable` → `res.Component != nil`, `Name=="curl"`,
  `RepoURL=="https://github.com/curl/curl"`, y persistido (un `GetComponent(spurl)`
  posterior lo encuentra).
- Un purl con Component real de ecosyste.ms → NO se sobreescribe.
- Un purl sin vulns y sin Component → `res.Component` queda `nil` (no se sintetiza
  ni se persiste).
- `go test .` verde (salvo el rojo pre-existente `TestAcceptCPE_SoleSingleCPE`).

## Depende de
- 012 (para que github traiga vulns y se dispare la síntesis)

## Notas
Decisiones tomadas: **persistir** en el store (aparece en /components, se cachea
como cualquier paquete; en el próximo collect `collectStage1` lo encuentra fresco
vía `GetComponent`). **Solo github** por ahora — gitlab/bitbucket requieren
extender la clasificación de purl (`isGitHubType`/`RepoURL`) + confirmar OSV-GIT
para esos hosts → task futura. No sintetizamos `Repository` (stars/forks/lang):
no tenemos esos datos, solo el `RepoURL` en el Component alcanza para el link.
`identity.Name` para github es el name del purl (`curl`).
