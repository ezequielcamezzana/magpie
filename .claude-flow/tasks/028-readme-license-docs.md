# Task 028: README, LICENSE, .env.example y docs en inglés

## Descripción
Cara pública del repo al nivel de meerkat: README real (hoy tiene una
línea), LICENSE, `.env.example` con las MAGPIE_* y docs en inglés.

## Pasos
1. README.md estilo meerkat: header centrado con ícono
   (`internal/server/ui/static/icon-512.png`), tagline, qué es magpie,
   quickstart (`magpie server`, SPA en `/app`), tabla de env vars,
   endpoints de la API, sección de desarrollo (make targets). En inglés.
2. LICENSE: misma licencia que meerkat (copiar y ajustar año/holder).
3. `.env.example` con todas las vars de `internal/server/config` y sus
   defaults comentados.
4. Revisar `docs/distro-packages.md`: si está en español, traducir; si
   quedó obsoleto tras el refactor, actualizar paths/nombres.

## Archivos afectados
- `README.md` — reescrito
- `LICENSE` — nuevo
- `.env.example` — nuevo
- `docs/distro-packages.md` — traducido/actualizado

## Definition of done
- README sin referencias a paths viejos (`httpapi/`, `pkg/`, `web/`).
- Toda env var de `config.Load()` aparece en README y `.env.example`.
- Cero contenido en español en archivos versionados (excepto
  `.claude-flow/`, que es tooling interno).

## Depende de
- 027
