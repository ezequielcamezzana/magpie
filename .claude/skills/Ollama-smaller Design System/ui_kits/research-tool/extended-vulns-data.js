/* Extended vulnerability dataset for the vuln/{CVE-id} page.
   The route id is a CVE; the page lists the source advisories tied to it as
   extended cards. Sources: "osv" (links to OSV + GitHub) or "ghsa" (GitHub only).
   Version fields are ARRAYS — affectedVersions in particular can be long, so the
   card renders them as a capped, expandable chip group. */
window.VULN_TARGET = "CVE-2026-44494";

window.EXTENDED_VULNS = [
  {
    OriginalID: "GHSA-35jp-ww65-95wh",
    CanonicalID: "CVE-2026-44494",
    Score: 8.7, CvssBucket: "high",
    Ecosystem: "npm",
    Source: "osv",
    Description:
      "A prototype-pollution gadget in axios' config.proxy handling lets an attacker controlling a malicious server poison Object.prototype, enabling a full man-in-the-middle on subsequent requests — including reading or rewriting request bodies and response data.",
    Published: "2026-05-29T16:04:00Z",
    Created: "2026-05-28T09:12:00Z",
    GithubUrl: "https://github.com/advisories/GHSA-35jp-ww65-95wh",
    OsvUrl: "https://osv.dev/vulnerability/GHSA-35jp-ww65-95wh",
    AffectedPackages: [
      {
        purl: "pkg:npm/axios",
        affectedVersions: [
          "1.0.0","1.1.0","1.1.3","1.2.0","1.2.6","1.3.0","1.3.6","1.4.0","1.5.0","1.5.1",
          "1.6.0","1.6.8","1.7.0","1.7.9","1.8.0","1.8.4","1.9.0","1.10.0","1.11.0","1.12.0",
          "1.13.0","1.14.0","1.15.0","1.15.1",
        ],
        affectedRanges: [">= 1.0.0, < 1.16.0", ">= 0.8.0, < 0.28.2"],
        unaffectedVersions: ["< 0.8.0"],
        fixedVersions: ["1.16.0", "0.28.2"],
      },
      {
        purl: "pkg:npm/@axios/proxy-agent",
        affectedVersions: ["0.1.0","0.2.0","0.3.0","0.4.0","0.4.1"],
        affectedRanges: [">= 0.0.0, < 0.5.0"],
        unaffectedVersions: [],
        fixedVersions: ["0.5.0"],
      },
    ],
  },
  {
    OriginalID: "GHSA-3g43-6gmg-66jw",
    CanonicalID: "CVE-2026-44494",
    Score: 7.0, CvssBucket: "high",
    Ecosystem: "npm",
    Source: "ghsa",
    Description:
      "Improper handling of nested configuration during config merge allows a prototype-pollution gadget that can leak credentials attached to outgoing requests and hijack the parsed response object.",
    Published: "2026-05-29T16:07:31Z",
    Created: "2026-05-29T11:40:00Z",
    GithubUrl: "https://github.com/advisories/GHSA-3g43-6gmg-66jw",
    OsvUrl: null,
    AffectedPackages: [
      {
        purl: "pkg:npm/axios",
        affectedVersions: [
          "1.0.0","1.2.0","1.4.0","1.6.0","1.8.0","1.10.0","1.12.0","1.14.0","1.15.0","1.15.1",
        ],
        affectedRanges: [">= 1.0.0, < 1.15.2"],
        unaffectedVersions: ["< 1.0.0"],
        fixedVersions: ["1.15.2"],
      },
    ],
  },
  {
    OriginalID: "GHSA-3p68-rc4w-qgx5",
    CanonicalID: "CVE-2026-44494",
    Score: 6.3, CvssBucket: "medium",
    Ecosystem: "npm",
    Source: "osv",
    Description:
      "axios normalizes NO_PROXY hostnames in a way that can be bypassed, letting a request that should have been excluded from proxying reach an internal address — a server-side request forgery (SSRF) vector.",
    Published: "2026-04-09T17:32:19Z",
    Created: "2026-04-08T14:05:00Z",
    GithubUrl: "https://github.com/advisories/GHSA-3p68-rc4w-qgx5",
    OsvUrl: "https://osv.dev/vulnerability/GHSA-3p68-rc4w-qgx5",
    AffectedPackages: [
      {
        purl: "pkg:npm/axios",
        affectedVersions: ["1.0.0","1.5.0","1.10.0","1.12.0","1.14.0"],
        affectedRanges: [">= 1.0.0, < 1.15.0"],
        unaffectedVersions: ["< 1.0.0"],
        fixedVersions: ["1.15.0"],
      },
    ],
  },
];
