# Task 003: source/osv — pickAffected tolerante al release (Truco 1)

## Descripción
Bug principal de "OSV no encuentra vulns" en Linux: `pickAffected` exige
igualdad exacta de ecosystem y cae a `affected[0]` (release equivocado). Para
Linux, elegir la entrada por prefix + release token. Plan P2.

## Pasos
1. En `source/osv/client.go`, reescribir `pickAffected(affected, q)`:
   - Para cada entrada: `p.Name == q.Name` y, según kind:
     - `KindLinux`: `strings.HasPrefix(p.Ecosystem, q.BaseEcosystem) &&
       (q.ReleaseToken == "" || strings.Contains(p.Ecosystem, q.ReleaseToken))`.
     - resto: `EqualFold(p.Ecosystem, q.Ecosystem)` (como hoy).
   - Sin match: `KindLinux` → `nil` (NO `affected[0]`); resto → `affected[0]`
     (fallback actual).
2. Verificar que `mapVuln` maneje `aff == nil` (ya retorna `rec` sin ranges).
3. Tests en `source/osv/client_test.go`: respuesta con `affected[]` multi-release
   (Ubuntu 22.04 + 24.04 + Debian) elige la del release consultado.

## Archivos afectados
- `source/osv/client.go` — `pickAffected`
- `source/osv/client_test.go` — caso multi-release

## Definition of done
- Query `Ubuntu:24.04` sobre una vuln con `affected[]` = [`Ubuntu:22.04:LTS`,
  `Ubuntu:24.04:LTS`] elige la `24.04` (no `affected[0]`).
- Query linux sin match real → la vuln queda sin `AffectedRanges` (no se atribuye
  el rango de otro release).
- Lenguaje (npm/pypi) mantiene el comportamiento actual.
- `go test ./source/osv/` verde.

## Depende de
- 002

## Notas
`q.ReleaseToken` y `q.BaseEcosystem` vienen de la task 002. Para redhat/suse/
fedora `ReleaseToken` puede venir vacío → matchea por prefix solamente
(aceptable, ver decisiones abiertas del plan).
