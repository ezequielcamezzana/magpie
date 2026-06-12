# Task 016: git init y limpieza de raíz

## Descripción
Magpie no es repo git y tiene basura en la raíz. Inicializar git, limpiar
artefactos y dejar un commit inicial limpio antes de empezar a mover código.

## Pasos
1. `git init` en la raíz del proyecto.
2. Borrar artefactos: binario `magpie`, `bin/`, `magpie.db`, `.DS_Store` (todos).
3. Crear `ai/` y mover ahí los mocks de diseño `CPE Match Cards.html` y
   `Component Page.html` (modelo meerkat: referencias de diseño viven en `ai/`).
4. Borrar los `.gitkeep` huérfanos (están en dirs que ya tienen archivos):
   `cmd/magpie/`, `httpapi/`, `pkg/match/`, `pkg/purl/`, `store/sqlite/`,
   `source/ecosystems/`, `source/nvd/`, `source/osv/`.
5. Borrar `source/cper/` (está vacío, el package real vive en `cper/`).
6. Extender `.gitignore`: agregar `/bin/`, `.DS_Store`.
7. Commit inicial con todo el código actual.

## Archivos afectados
- `magpie`, `bin/magpie`, `magpie.db` — borrados
- `CPE Match Cards.html`, `Component Page.html` — movidos a `ai/`
- `source/cper/` — borrado
- `.gitignore` — modificado
- `*/.gitkeep` — borrados

## Definition of done
- `git log` muestra el commit inicial.
- `git status` limpio.
- `find . -name .gitkeep -not -path './.git/*'` no devuelve nada.
- `ls` en raíz no muestra binarios, `.db` ni HTML sueltos.
- `go build ./...` y `go test ./...` verdes (nada de código se tocó).

## Depende de
- ninguna
