/* ComponentCard — square-ish grid tile for one dependency/component.
   Top row: package icon + GitHub link (only when RepoUrl exists).
   Body: name, version, ecosystem pill.
   Depends on tokens.css + base.css + vulncard.css + lucide. */

function ComponentCard({ comp }) {
  React.useEffect(() => { if (window.lucide) window.lucide.createIcons(); });
  return (
    <div className="cmp">
      <div className="cmp-row">
        <span className="cmp-icon"><i data-lucide="package"></i></span>
        {comp.RepoUrl && (
          <a className="cmp-repo" href={comp.RepoUrl} target="_blank" rel="noreferrer" aria-label="GitHub repository">
            <i data-lucide="github"></i>
          </a>
        )}
      </div>
      <div className="cmp-body">
        <div className="cmp-name">{comp.Name}</div>
        {comp.Version && <div className="cmp-ver">{comp.Version}</div>}
      </div>
      <span className="cmp-eco">{comp.Ecosystem}</span>
    </div>
  );
}

Object.assign(window, { ComponentCard });
