/* Topbar — logo + wordmark + plain-text nav (active underlined); actions right.
   Borderless, sticky, 56px. The logo image is the app's one spot of color. */
function Topbar({ tab, onTab, onNewScan, signedIn, onSignIn }) {
  const links = ["Advisories", "Packages", "Sources"];
  return (
    <nav className="nav">
      <div className="nav-left">
        <a className="nav-brand" href="#" onClick={(e)=>{e.preventDefault();onTab("Advisories");}}>
          <img className="nav-logo" src="ui/app-icon.svg" alt="" />
          advisories
        </a>
        <div className="nav-links">
          {links.map((l) => (
            <a key={l} className={"nav-link" + (tab === l ? " active" : "")}
               href="#" onClick={(e)=>{e.preventDefault();onTab(l);}}>{l}</a>
          ))}
        </div>
      </div>
      <div className="nav-actions">
        {signedIn
          ? <span className="badge">signed in</span>
          : <button className="btn-secondary" onClick={onSignIn}>Sign in</button>}
        <button className="btn-primary" onClick={onNewScan}>New scan</button>
      </div>
    </nav>
  );
}
window.Topbar = Topbar;
