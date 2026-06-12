/* NewScanModal — pill inputs, ink primary action. The dark scrim is the one
   permitted "look here" elevation. */
function NewScanModal({ onClose, onRun }) {
  const [target, setTarget] = React.useState("");
  const [minSev, setMinSev] = React.useState("all");
  return (
    <div className="scrim" onClick={onClose}>
      <div className="modal" onClick={(e)=>e.stopPropagation()}>
        <h2>New scan</h2>
        <div className="modal-field">
          <label>Package or lockfile</label>
          <input className="input-pill" placeholder="e.g. openssl@3.2.1 or package-lock.json"
                 value={target} onChange={(e)=>setTarget(e.target.value)} autoFocus />
        </div>
        <div className="modal-field">
          <label>Minimum severity</label>
          <select className="select-pill" style={{width:"100%"}} value={minSev} onChange={(e)=>setMinSev(e.target.value)}>
            <option value="all">Report everything</option>
            <option value="low">Low and above</option>
            <option value="medium">Medium and above</option>
            <option value="high">High and above</option>
          </select>
        </div>
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!target.trim()} onClick={()=>onRun(target)}>Run scan</button>
        </div>
      </div>
    </div>
  );
}
window.NewScanModal = NewScanModal;
