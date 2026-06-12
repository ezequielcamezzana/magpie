# Task 030: (meerkat) portar las prácticas adoptadas de magpie

## Descripción
**Esta task se ejecuta en `../meerkat`, no en magpie.** Portar a meerkat
las tres prácticas de magpie que quedaron como estándar: package docs,
Makefile documentado y `ui-sync` del design system compartido.

## Pasos
1. Agregar `// Package x ...` (una o dos líneas, en inglés) a cada package
   de `internal/` y `pkg/api` que no lo tenga. No duplicar lo que ya diga
   un type doc.
2. Makefile: adoptar el formato de magpie — targets documentados con `##`,
   binario en `bin/`, agregar `run`, `vet`, `fmt`, `tidy`. Mantener los
   LDFLAGS existentes.
3. Agregar target `ui-sync` que copie `tokens.css`/`base.css` desde
   `~/Proyectos/apps/ui` a donde viva el CSS de `internal/server/ui/`
   (revisar estructura actual de assets antes; si la UI de meerkat no
   consume tokens.css/base.css todavía, dejar el target listo y anotar
   la integración como pendiente con un `TODO:`).
4. Actualizar `.gitignore` de meerkat con `/bin/` y limpiar la raíz
   (binario `meerkat`, `test.json`, `severity-colors.txt`, `project.json`
   — confirmar antes de borrar que no los usa nada).

## Archivos afectados
- `../meerkat/internal/**/*.go` — package docs agregados
- `../meerkat/Makefile` — formato documentado + targets nuevos
- `../meerkat/.gitignore` — `/bin/`
- raíz de meerkat — limpieza

## Definition of done
- Todo package de meerkat tiene package doc:
  `go vet ./...` verde y revisión con `go doc ./internal/...`.
- `make build` deja el binario en `bin/meerkat`; `make run`, `make vet`,
  `make fmt`, `make tidy` funcionan.
- `make ui-sync` copia los archivos del design system.
- `go test ./...` verde (nada funcional cambió).

## Notas
Independiente de las tasks de magpie: se puede hacer en paralelo.
La limpieza de raíz (paso 4) requiere confirmar con el usuario qué
archivos son descartables antes de borrar.

## Depende de
- ninguna
