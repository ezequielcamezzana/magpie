# Task 004: source/osv — merge de `upstream` en aliases (Truco 2)

## Descripción
Entradas `DEBIAN-CVE-*` (y varias de Ubuntu) dejan `aliases` vacío y ponen el
CVE canónico en el campo OSV `upstream`. Sin mergearlo, los vulns de distro no
tienen alias CVE → CPER no camina a NVD y el grouping no dedupea. Plan P3.

## Pasos
1. En `source/osv/types.go`, agregar `Upstream []string \`json:"upstream"\`` al
   `rawVuln`.
2. Agregar helper `mergeUnique(a, b []string) []string` (drop vacíos y
   duplicados, preserva orden) — o reutilizar uno existente.
3. En `source/osv/client.go` `mapVuln`, cambiar `Aliases: v.Aliases` por
   `Aliases: mergeUnique(v.Aliases, v.Upstream)`.
4. Tests en `source/osv/client_test.go`: vuln con `aliases:[]` y
   `upstream:["CVE-..."]` produce `Aliases` con el CVE.

## Archivos afectados
- `source/osv/types.go` — campo `Upstream`
- `source/osv/client.go` — `mergeUnique` + uso en `mapVuln`
- `source/osv/client_test.go` — caso upstream

## Definition of done
- `mapVuln` sobre `{id:"DEBIAN-CVE-2023-1", aliases:[], upstream:["CVE-2023-1"]}`
  → `Aliases == ["CVE-2023-1"]`.
- Duplicados entre `aliases` y `upstream` no se repiten.
- `go test ./source/osv/` verde.

## Depende de
- ninguna

## Notas
Independiente del resto; se puede hacer en cualquier momento. Holmes:
`osv.go:283-286` + `mergeUniqueIDs`.
