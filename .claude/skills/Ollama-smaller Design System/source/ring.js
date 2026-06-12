/* renderRing — build a segmented donut as an SVG string.
   Load via <script src="ui/ring.js"></script>; renderRing becomes global.

   Segments: [{ value, sev }] where sev is a severity key
   (critical|high|medium|low|none). Omit sev to fall back to a neutral grey
   ramp by index. Color comes only from severity or grey — never brand.

   Example:
     el.innerHTML = renderRing([
       { value: 3, sev: 'critical' },
       { value: 5, sev: 'high' },
     ]);
*/

const RING_SEVERITY = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308",
  low: "#94a3b8", none: "#cbd5e1",
};
// Charcoal → hairline. Used for non-severity (neutral) segments.
const RING_GREYS = ["#525252", "#737373", "#a3a3a3", "#d4d4d4"];
const RING_TRACK = "#e5e5e5";

function renderRing(segments, opts = {}) {
  const size = opts.size || 160;
  const sw = opts.strokeWidth || 22;
  const c = size / 2;
  const r = c - sw / 2;
  const circ = 2 * Math.PI * r;
  const total = segments.reduce((s, x) => s + (x.value || 0), 0);

  const track = `<circle r="${r}" cx="${c}" cy="${c}" fill="none" stroke="${RING_TRACK}" stroke-width="${sw}"/>`;

  let segs = "";
  if (total > 0) {
    let cum = 0, gi = 0;
    segs = segments
      .map((seg) => {
        const v = seg.value || 0;
        if (!v) return "";
        const color = seg.sev
          ? RING_SEVERITY[seg.sev] || RING_TRACK
          : RING_GREYS[gi++ % RING_GREYS.length];
        const arc = (v / total) * circ;
        // dashoffset = circ/4 - cum starts the first segment at 12 o'clock.
        const out = `<circle r="${r}" cx="${c}" cy="${c}" fill="none" stroke="${color}" stroke-width="${sw}" stroke-dasharray="${arc.toFixed(2)} ${(circ - arc).toFixed(2)}" stroke-dashoffset="${(circ / 4 - cum).toFixed(2)}"/>`;
        cum += arc;
        return out;
      })
      .join("");
  }

  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">${track}${segs}</svg>`;
}
