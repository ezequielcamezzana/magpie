/* GroupedVulnCard — root canonical advisory + collapsible source-record children.
   Depends on tokens.css + base.css + vulncard.css. No other libs. */

// Demo "today" so relative times read sensibly against the sample data.
const VC_NOW = new Date("2026-06-02T00:00:00Z");

function vcBucket(score) {
  if (score == null) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}
function vcFmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}/${p(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}`;
}
function vcRel(iso) {
  if (!iso) return "";
  const days = Math.round((VC_NOW - new Date(iso)) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "1 day ago";
  if (days < 30) return `${days} days ago`;
  const months = Math.round(days / 30);
  if (months < 12) return months === 1 ? "1 month ago" : `${months} months ago`;
  const years = Math.round(days / 365);
  return years === 1 ? "1 year ago" : `${years} years ago`;
}

/* One score pill: TYPE · SCORE · BUCKET, tinted+bordered by bucket. */
function VcScorePill({ type, score, bucket, info, title }) {
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

function VulnChild({ m }) {
  const r = m.Record, v = m.Verdict;
  const matched = v.Matched;
  return (
    <div className="vc-child">
      <div className="vc-child-main">
        <div className="vc-child-pills">
          <span className="vc-id">{r.OriginalID} <span className="vc-src">({r.Source})</span></span>
          <VcScorePill type="CVSS" score={Number(r.Score).toFixed(1)} bucket={vcBucket(r.Score)} />
        </div>

        <div className="vc-desc">{r.Title}</div>

        <div className={"vc-match " + (matched ? "is-match" : "no-match")}>
          <span className="vc-dot"></span>
          <span className="vc-ver">{m.scannedVersion}</span>
          <span className="vc-reason">{v.Reason.replace(/_/g, " ")}</span>
          {v.Range && <span className="vc-range">{v.Range}</span>}
          {matched && v.NextFix && <span className="vc-fix">→ fixed in {v.NextFix}</span>}
        </div>
      </div>

      <div className="vc-dates">
        <div><span className="vc-dlabel">Published</span> {vcFmtDate(r.Published)} <span className="vc-rel">({vcRel(r.Published)})</span></div>
        <div><span className="vc-dlabel">Updated</span> {vcFmtDate(r.Modified)} <span className="vc-rel">({vcRel(r.Modified)})</span></div>
      </div>
    </div>
  );
}

function GroupedVulnCard({ group, defaultOpen = false }) {
  const [open, setOpen] = React.useState(defaultOpen);
  const n = group.Members.length;
  const bucket = vcBucket(group.MaxScore);
  const exsBucket = group.ExposureBucket || vcBucket(group.ExposureScore);
  // thread the scanned version onto each member for the child renderer
  const members = group.Members.map((m) => ({ ...m, scannedVersion: group.scannedVersion }));

  return (
    <div className={"vc-card" + (open ? " is-open" : "") + (group.Affected ? "" : " is-unaffected")}>
      <button className="vc-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="vc-canonical">{group.CanonicalID}</span>

        <span className="vc-head-right">
          {group.Affected ? (
            <React.Fragment>
              <VcScorePill
                type="ExS" score={group.ExposureScore} bucket={exsBucket} info
                title="Exposure Score — severity × scope weight × kind weight" />
              <VcScorePill
                type="CVSS" score={Number(group.MaxScore).toFixed(1)} bucket={bucket} />
            </React.Fragment>
          ) : (
            <span className="vc-na">not affected</span>
          )}
          <span className="vc-count">
            {n} {n === 1 ? "source" : "sources"}
            <span className={"vc-chev" + (open ? " open" : "")}>▶</span>
          </span>
        </span>
      </button>

      {open && (
        <div className="vc-children">
          {members.map((m, i) => <VulnChild key={i} m={m} />)}
        </div>
      )}
    </div>
  );
}

Object.assign(window, { GroupedVulnCard, VulnChild, VcScorePill, vcBucket, vcFmtDate, vcRel });
