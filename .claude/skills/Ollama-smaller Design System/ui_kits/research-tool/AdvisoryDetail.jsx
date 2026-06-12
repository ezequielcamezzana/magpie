/* AdvisoryDetail — single advisory view. Back link, head + sev chip, key/value
   grid, description, a collapsible affected-versions list, and a code block. */
function AdvisoryDetail({ adv, onBack }) {
  const [open, setOpen] = React.useState(true);
  return (
    <div className="page">
      <div className="container">
        <button className="back-link" onClick={onBack}>‹ All advisories</button>

        <div className="detail-head">
          <div>
            <div className="detail-title">{adv.name}</div>
            <div className="adv-id" style={{marginTop:8}}>{adv.id}</div>
          </div>
          <span className={"sev sev-" + adv.sev}>{adv.sev.toUpperCase()}</span>
        </div>

        <div className="detail-grid">
          <div className="kv"><div className="k">Package</div><div className="v">{adv.pkg}</div></div>
          <div className="kv"><div className="k">CVSS</div><div className="v">{adv.cvss}</div></div>
          <div className="kv"><div className="k">Fixed in</div><div className="v">{adv.fixed}</div></div>
          <div className="kv"><div className="k">Affected</div><div className="v">{adv.versions}</div></div>
          <div className="kv"><div className="k">Source</div><div className="v">{adv.source}</div></div>
          <div className="kv"><div className="k">Published</div><div className="v">{adv.date}</div></div>
        </div>

        <div className="detail-section">
          <h3>Summary</h3>
          <p>{adv.summary}</p>
        </div>

        <div className="detail-section">
          <div className={"collapse" + (open ? " open" : "")}>
            <div className="collapse-header" onClick={()=>setOpen(!open)}>
              <span className="collapse-chevron">▶</span>
              <span className="ds-label" style={{fontWeight:600,color:"var(--color-ink)"}}>Remediation</span>
            </div>
            <div className="collapse-body" style={{marginTop:12}}>
              <pre className="code-block">{`# upgrade to the fixed release
npm install ${adv.pkg}@${adv.fixed}

# verify the resolved version
npm ls ${adv.pkg}`}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
window.AdvisoryDetail = AdvisoryDetail;
