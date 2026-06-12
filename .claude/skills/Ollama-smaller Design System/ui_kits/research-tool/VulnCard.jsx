/* VulnCard — compact single advisory card (mirrors the vuln/{id} page).
   Header: OriginalID (CanonicalID) + CVSS pill + source pill.
   Links: GitHub advisory (always) + OSV (only when Source === "osv").
   Dates: published + updated, DD/MM/YYYY (rel). No description.
   Depends on tokens.css + base.css + vulncard.css + lucide. */

const VC_NOW = new Date("2026-06-04T00:00:00Z");

function svcBucket(score) {
  if (score == null) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}
function svcDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso), p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}/${p(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}`;
}
function svcRel(iso) {
  if (!iso) return "";
  const days = Math.round((VC_NOW - new Date(iso)) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "1 day ago";
  if (days < 30) return `${days} days ago`;
  const m = Math.round(days / 30);
  if (m < 12) return m === 1 ? "1 month ago" : `${m} months ago`;
  const y = Math.round(days / 365);
  return y === 1 ? "1 year ago" : `${y} years ago`;
}

/* One score pill: TYPE · SCORE · BUCKET, tinted by bucket. */
function ScorePill({ type, score, bucket, info, title }) {
  return (
    <span className={"svc-score sev-" + bucket} title={title}>
      <span className="svc-score-type">{type}</span>
      <span className="svc-score-sep">·</span>
      <span className="svc-score-val">{score}</span>
      <span className="svc-score-sep">·</span>
      <span className="svc-score-bucket">{bucket}</span>
      {info && <span className="svc-score-info">ⓘ</span>}
    </span>
  );
}

function VulnCard({ rec }) {
  const cvssBucket = rec.CvssBucket || svcBucket(rec.Score);
  React.useEffect(() => { if (window.lucide) window.lucide.createIcons(); });

  return (
    <div className="svc">
      <div className="svc-top">
        <div className="svc-title-wrap">
          <span className="svc-canonical">{rec.OriginalID}</span>
          {rec.CanonicalID && <span className="svc-paren">({rec.CanonicalID})</span>}
        </div>
        <div className="svc-scores">
          <ScorePill type="CVSS" score={Number(rec.Score).toFixed(1)} bucket={cvssBucket} />
          <span className="svc-src-pill">{rec.Source}</span>
        </div>
      </div>

      <div className="evc-links">
        <a className="evc-link" href={rec.GithubUrl} target="_blank" rel="noreferrer">
          <i data-lucide="github"></i> GitHub advisory
        </a>
        {rec.Source === "osv" && rec.OsvUrl && (
          <a className="evc-link" href={rec.OsvUrl} target="_blank" rel="noreferrer">
            <i data-lucide="external-link"></i> OSV
          </a>
        )}
      </div>

      <div className="evc-dates">
        <span><span className="evc-dlabel">Published</span> {svcDate(rec.Published)} <span className="evc-rel">({svcRel(rec.Published)})</span></span>
        <span className="evc-dot">·</span>
        <span><span className="evc-dlabel">Updated</span> {svcDate(rec.Updated)} <span className="evc-rel">({svcRel(rec.Updated)})</span></span>
      </div>
    </div>
  );
}

Object.assign(window, { VulnCard, ScorePill, svcBucket });
