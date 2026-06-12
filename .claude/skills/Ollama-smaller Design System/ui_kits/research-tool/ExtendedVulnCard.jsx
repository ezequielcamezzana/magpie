/* ExtendedVulnCard — full vulnerability card for the vuln/{id} page.
   Header: OriginalID (CanonicalID) + CVSS pill + ecosystem pill.
   Links: GitHub advisory (always) + OSV (only when Source === "osv").
   Description + published/created dates (DD/MM/YYYY (rel)).
   Collapsible per affected package: purl + version detail.
   Depends on tokens.css + base.css + vulncard.css + lucide. */

const EVC_NOW = new Date("2026-06-04T00:00:00Z");

function evcBucket(score) {
  if (score == null) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}
function evcDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso), p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}/${p(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}`;
}
function evcRel(iso) {
  if (!iso) return "";
  const days = Math.round((EVC_NOW - new Date(iso)) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "1 day ago";
  if (days < 30) return `${days} days ago`;
  const m = Math.round(days / 30);
  if (m < 12) return m === 1 ? "1 month ago" : `${m} months ago`;
  const y = Math.round(days / 365);
  return y === 1 ? "1 year ago" : `${y} years ago`;
}

/* A capped, expandable chip group for version lists (can be long). */
function VersionChips({ items, cap = 12, empty = "—" }) {
  const [open, setOpen] = React.useState(false);
  const list = items || [];
  if (!list.length) return <span className="evc-empty">{empty}</span>;
  const shown = open ? list : list.slice(0, cap);
  const hidden = list.length - shown.length;
  return (
    <span className="evc-chips">
      {shown.map((v, i) => <span className="evc-ver" key={i}>{v}</span>)}
      {hidden > 0 && (
        <button className="evc-more" onClick={() => setOpen(true)}>+{hidden} more</button>
      )}
      {open && list.length > cap && (
        <button className="evc-more" onClick={() => setOpen(false)}>show less</button>
      )}
    </span>
  );
}

/* One affected-package collapsible. */
function AffectedPackage({ pkg, defaultOpen }) {
  const [open, setOpen] = React.useState(!!defaultOpen);
  const fixed = pkg.fixedVersions || [];
  return (
    <div className={"evc-pkg collapse" + (open ? " open" : "")}>
      <div className="evc-pkg-head collapse-header" onClick={() => setOpen(!open)}>
        <span className="collapse-chevron">▶</span>
        <span className="evc-purl">{pkg.purl}</span>
        {fixed.length > 0 && <span className="evc-pkg-fix">fixed in {fixed[0]}</span>}
      </div>
      <div className="collapse-body">
        <dl className="evc-kv">
          <div className="evc-kv-row">
            <dt>Affected</dt>
            <dd><VersionChips items={pkg.affectedVersions} /></dd>
          </div>
          <div className="evc-kv-row">
            <dt>Affected ranges</dt>
            <dd><span className="evc-chips">{(pkg.affectedRanges || []).map((r, i) => <span className="evc-range" key={i}>{r}</span>)}</span></dd>
          </div>
          <div className="evc-kv-row">
            <dt>Unaffected</dt>
            <dd><VersionChips items={pkg.unaffectedVersions} /></dd>
          </div>
          <div className="evc-kv-row">
            <dt>Fixed</dt>
            <dd><VersionChips items={pkg.fixedVersions} /></dd>
          </div>
        </dl>
      </div>
    </div>
  );
}

function ExtendedVulnCard({ vuln }) {
  const bucket = vuln.CvssBucket || evcBucket(vuln.Score);
  const pkgs = vuln.AffectedPackages || [];
  return (
    <article className="evc">
      <header className="evc-head">
        <div className="evc-title-wrap">
          <h2 className="evc-title">{vuln.OriginalID}</h2>
          {vuln.CanonicalID && <span className="evc-canonical">({vuln.CanonicalID})</span>}
        </div>
        <div className="evc-pills">
          <span className={"svc-score sev-" + bucket}>
            <span className="svc-score-type">CVSS</span>
            <span className="svc-score-sep">·</span>
            <span className="svc-score-val">{Number(vuln.Score).toFixed(1)}</span>
            <span className="svc-score-sep">·</span>
            <span className="svc-score-bucket">{bucket}</span>
          </span>
          <span className="evc-eco">{vuln.Ecosystem}</span>
        </div>
      </header>

      <div className="evc-links">
        <a className="evc-link" href={vuln.GithubUrl} target="_blank" rel="noreferrer">
          <i data-lucide="github"></i> GitHub advisory
        </a>
        {vuln.Source === "osv" && vuln.OsvUrl && (
          <a className="evc-link" href={vuln.OsvUrl} target="_blank" rel="noreferrer">
            <i data-lucide="external-link"></i> OSV
          </a>
        )}
      </div>

      <p className="evc-desc">{vuln.Description}</p>

      <div className="evc-dates">
        <span><span className="evc-dlabel">Published</span> {evcDate(vuln.Published)} <span className="evc-rel">({evcRel(vuln.Published)})</span></span>
        <span className="evc-dot">·</span>
        <span><span className="evc-dlabel">Created</span> {evcDate(vuln.Created)} <span className="evc-rel">({evcRel(vuln.Created)})</span></span>
      </div>

      <div className="evc-affected">
        <div className="evc-affected-label">Affected packages <span className="evc-count">{pkgs.length}</span></div>
        <div className="evc-pkg-list">
          {pkgs.map((p, i) => (
            <AffectedPackage key={p.purl} pkg={p} defaultOpen={pkgs.length === 1 || i === 0} />
          ))}
        </div>
      </div>
    </article>
  );
}

Object.assign(window, { ExtendedVulnCard, AffectedPackage, VersionChips, evcBucket, evcDate, evcRel });
