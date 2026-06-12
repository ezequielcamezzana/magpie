/* Footer — meta left (brand · version · year), external links right.
   The only home for GitHub/Docs/Install. Lucide glyphs (CDN substitution). */
function Footer() {
  React.useEffect(() => { if (window.lucide) window.lucide.createIcons(); });
  return (
    <footer className="footer container">
      <span className="footer-meta">advisories · v0.4.1 · 2026</span>
      <div className="footer-links">
        <a className="icon-link" href="#" aria-label="GitHub"><i data-lucide="github"></i></a>
        <a className="icon-link" href="#" aria-label="Docs"><i data-lucide="book-open"></i></a>
        <a className="icon-link" href="#" aria-label="Install"><i data-lucide="download"></i></a>
      </div>
    </footer>
  );
}
window.Footer = Footer;
