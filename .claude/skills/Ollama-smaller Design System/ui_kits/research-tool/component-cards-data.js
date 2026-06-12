/* Component (package) records. A component is one dependency in the SBOM.
   - Name      = package name
   - Ecosystem = npm / pypi / cargo / go / maven …
   - RepoUrl   = source repo; when present the card links to GitHub */
window.COMPONENTS = [
  { Name: "axios",            Ecosystem: "npm",   Version: "1.12.0", RepoUrl: "https://github.com/axios/axios" },
  { Name: "lodash",           Ecosystem: "npm",   Version: "4.17.21", RepoUrl: "https://github.com/lodash/lodash" },
  { Name: "requests",         Ecosystem: "pypi",  Version: "2.32.3", RepoUrl: "https://github.com/psf/requests" },
  { Name: "serde",            Ecosystem: "cargo", Version: "1.0.210", RepoUrl: "https://github.com/serde-rs/serde" },
  { Name: "internal-utils",   Ecosystem: "npm",   Version: "0.4.1", RepoUrl: null },
  { Name: "golang.org/x/net", Ecosystem: "go",    Version: "0.38.0", RepoUrl: "https://github.com/golang/net" },
];
