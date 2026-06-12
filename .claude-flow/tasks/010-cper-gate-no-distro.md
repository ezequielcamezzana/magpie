# Task 010: CPER — gatear a no-distro (skip KindLinux)

## Descripción
CPE apunta al código upstream; un purl distro apunta a una distribución de ese
código (con fixes backporteados). Aplicar rangos/CPE de NVD a un paquete distro
genera **falsos positivos** (NVD dice vulnerable hasta 8.4.0; Debian backporteó
el fix en 7.88.1-10+deb12u4 → el paquete está fixeado pero NVD lo marcaría
afectado). Para distros la fuente autoritativa es OSV (backport-aware). Por eso
CPER/NVD-by-CPE NO debe correr para `KindLinux`. Decisión de diseño tras el
smoke de curl.

## Pasos
1. En `runCPER` (`cper.go`), early-return si `id.Kind == purl.KindLinux`, con un
   comentario `// WHY:` explicando backports → falsos positivos.
2. Verificar que stage 4 (NVD-by-CPE) no corra para distros como consecuencia
   (CPER no persiste CPEs → no hay CPE para querear NVD).
3. Test: un `Collect` (o `runCPER` directo) de un purl `KindLinux` no produce
   CPEs ni records NVD, aunque haya NVD key configurada.

## Archivos afectados
- `cper.go` — early-return en `runCPER` para `KindLinux`
- `cper_test.go` o `cper_e2e_test.go` — caso distro no resuelve CPE

## Definition of done
- `runCPER` con `id.Kind == KindLinux` retorna sin tocar NVD ni `PutCPEs`.
- Un purl distro (`pkg:deb/debian/curl@…`) nunca tiene `Result.CPEs` ni records
  `source=nvd`, aun con `NVDAPIKey` seteada.
- CPER sigue corriendo normal para `KindLanguage`.
- `go test .` verde (salvo el rojo pre-existente `TestAcceptCPE_SoleSingleCPE`,
  no relacionado).

## Depende de
- ninguna

## Notas
CPER sigue valiendo para lenguajes (npm/pypi/…) donde OSV y NVD comparten
esquema de versión. Esto solo lo saltea para distros. Si más adelante se quiere
el CPE como dato **informativo** en la UI (link al producto upstream), debe ir
por un campo separado que NUNCA alimente verdicts — fuera de scope acá.
