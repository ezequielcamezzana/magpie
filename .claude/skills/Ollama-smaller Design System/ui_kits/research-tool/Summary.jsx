/* Summary — severity ring (renderRing) + total stats on a hairline card. */
function Summary({ advisories }) {
  const ref = React.useRef(null);
  const counts = { critical:0, high:0, medium:0, low:0, none:0 };
  advisories.forEach((a) => { counts[a.sev] = (counts[a.sev]||0) + 1; });

  React.useEffect(() => {
    if (ref.current && window.renderRing) {
      ref.current.innerHTML = window.renderRing([
        { value: counts.critical, sev:"critical" },
        { value: counts.high, sev:"high" },
        { value: counts.medium, sev:"medium" },
        { value: counts.low, sev:"low" },
      ], { size:128, strokeWidth:20 });
    }
  }, [advisories]);

  const legend = [
    ["critical","Critical","#ef4444"], ["high","High","#f97316"],
    ["medium","Medium","#eab308"], ["low","Low","#94a3b8"],
  ];

  return (
    <div className="card summary">
      <div className="ring-wrap" ref={ref}></div>
      <div className="ring-legend">
        {legend.map(([k,label,c]) => (
          <div key={k} className="ring-legend-item">
            <span className="ring-swatch" style={{background:c}}></span>
            {label}<span className="c">{counts[k]}</span>
          </div>
        ))}
      </div>
      <div className="summary-totals">
        <div className="summary-stat"><div className="n">{advisories.length}</div><div className="l">open advisories</div></div>
        <div className="summary-stat"><div className="n">{counts.critical + counts.high}</div><div className="l">high or critical</div></div>
      </div>
    </div>
  );
}
window.Summary = Summary;
