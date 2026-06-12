/* AdvisoryCard — hairline card, severity chip, mono id + package. */
function AdvisoryCard({ adv, onOpen }) {
  return (
    <div className="card adv-card" onClick={() => onOpen(adv)}>
      <div className="adv-top">
        <div>
          <div className="adv-name">{adv.name}</div>
          <div className="adv-id">{adv.id}</div>
        </div>
        <span className={"sev sev-" + adv.sev}>{adv.sev.toUpperCase()}</span>
      </div>
      <div className="adv-summary">{adv.summary}</div>
      <div className="adv-meta">
        <span>{adv.pkg} {adv.versions}</span>
        <span className="dot">·</span>
        <span>CVSS {adv.cvss}</span>
        <span className="dot">·</span>
        <span>fixed {adv.fixed}</span>
        <span className="dot">·</span>
        <span>{adv.date}</span>
      </div>
    </div>
  );
}
window.AdvisoryCard = AdvisoryCard;

/* AdvisoryList — filter bar (search + selects on the left, pager on the right,
   one line) above the data, then the list. */
function AdvisoryList({ advisories, onOpen }) {
  const [q, setQ] = React.useState("");
  const [sev, setSev] = React.useState("all");
  const [sort, setSort] = React.useState("severity");
  const [page, setPage] = React.useState(0);
  const PER = 4;
  const sevRank = { critical:4, high:3, medium:2, low:1, none:0 };

  let rows = advisories.filter((a) => {
    const m = (a.name + " " + a.id + " " + a.pkg).toLowerCase().includes(q.toLowerCase());
    return m && (sev === "all" || a.sev === sev);
  });
  rows = rows.slice().sort((a,b) =>
    sort === "severity" ? sevRank[b.sev]-sevRank[a.sev] : b.date.localeCompare(a.date));

  const total = Math.max(1, Math.ceil(rows.length / PER));
  const p = Math.min(page, total - 1);
  const shown = rows.slice(p*PER, p*PER + PER);

  React.useEffect(() => { setPage(0); }, [q, sev, sort]);

  return (
    <div className="section">
      <div className="filter-bar">
        <div className="filter-left">
          <input className="search-input" placeholder="Search advisories…"
                 value={q} onChange={(e)=>setQ(e.target.value)} />
          <select className="select-pill" value={sev} onChange={(e)=>setSev(e.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="select-pill" value={sort} onChange={(e)=>setSort(e.target.value)}>
            <option value="severity">Sort: severity</option>
            <option value="date">Sort: newest</option>
          </select>
        </div>
        <div className="pager">
          <span>{rows.length} results</span>
          <button className="page-btn" disabled={p===0} onClick={()=>setPage(p-1)}>‹</button>
          <span>{p+1} / {total}</span>
          <button className="page-btn" disabled={p>=total-1} onClick={()=>setPage(p+1)}>›</button>
        </div>
      </div>

      {shown.length ? (
        <div className="adv-list">
          {shown.map((a) => <AdvisoryCard key={a.id} adv={a} onOpen={onOpen} />)}
        </div>
      ) : (
        <div className="empty">No advisories match your filters.</div>
      )}
    </div>
  );
}
window.AdvisoryList = AdvisoryList;
