/* Flat single-advisory records (one card each) — real fields from the scan.
   - Score          = CVSS score (v.severity_score)
   - CvssBucket     = CVSS v3 bucket (0 none · .1-3.9 low · 4-6.9 medium · 7-8.9 high · 9-10 critical)
   - Source         = "osv" gets an OSV link; others (e.g. ecosyste.ms) GitHub only
   - Published / Updated = ISO dates, rendered DD/MM/YYYY (rel) */
window.VULN_RECORDS = [
  {
    CanonicalID: "CVE-2026-44494", OriginalID: "GHSA-35jp-ww65-95wh",
    Aliases: ["GHSA-35jp-ww65-95wh", "CVE-2026-44494"], Source: "osv",
    Score: 8.7, CvssBucket: "high",
    Package: "axios",
    Title: "axios Vulnerable to Full Man-in-the-Middle via Prototype Pollution Gadget in config.proxy",
    AffectedRange: "[1.0.0, 1.16.0)", FixedVersion: "1.16.0",
    Published: "2026-05-29T16:04:00Z", Updated: "2026-06-01T20:14:14Z",
    GithubUrl: "https://github.com/advisories/GHSA-35jp-ww65-95wh",
    OsvUrl: "https://osv.dev/vulnerability/GHSA-35jp-ww65-95wh",
  },
  {
    CanonicalID: "CVE-2026-44495", OriginalID: "GHSA-3g43-6gmg-66jw",
    Aliases: ["GHSA-3g43-6gmg-66jw", "CVE-2026-44495"], Source: "ecosyste.ms",
    Score: 7, CvssBucket: "high",
    Package: "axios",
    Title: "axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pollution Gadget in Config Merge",
    AffectedRange: "[1.0.0, 1.15.2)", FixedVersion: "1.15.2",
    Published: "2026-05-29T16:07:31Z", Updated: "2026-05-30T19:00:10Z",
    GithubUrl: "https://github.com/advisories/GHSA-3g43-6gmg-66jw",
    OsvUrl: null,
  },
  {
    CanonicalID: "CVE-2025-62718", OriginalID: "GHSA-3p68-rc4w-qgx5",
    Aliases: ["GHSA-3p68-rc4w-qgx5", "CVE-2025-62718"], Source: "osv",
    Score: 6.3, CvssBucket: "medium",
    Package: "axios",
    Title: "Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF",
    AffectedRange: "[1.0.0, 1.15.0)", FixedVersion: "1.15.0",
    Published: "2026-04-09T17:32:19Z", Updated: "2026-05-08T13:46:43Z",
    GithubUrl: "https://github.com/advisories/GHSA-3p68-rc4w-qgx5",
    OsvUrl: "https://osv.dev/vulnerability/GHSA-3p68-rc4w-qgx5",
  },
  {
    CanonicalID: "CVE-2026-42044", OriginalID: "GHSA-3w6x-2g7m-8v23",
    Aliases: ["GHSA-3w6x-2g7m-8v23", "CVE-2026-42044"], Source: "ecosyste.ms",
    Score: 6.5, CvssBucket: "medium",
    Package: "axios",
    Title: "Axios: Invisible JSON Response Tampering via Prototype Pollution Gadget in parseReviver",
    AffectedRange: "[1.0.0, 1.15.2)", FixedVersion: "1.15.2",
    Published: "2026-05-05T00:19:33Z", Updated: "2026-05-06T15:29:23Z",
    GithubUrl: "https://github.com/advisories/GHSA-3w6x-2g7m-8v23",
    OsvUrl: null,
  },
];
