/* Grouped-vulnerability dataset — extracted verbatim from the scan output.
   Each group is one canonical advisory aggregated from multiple sources
   (ecosyste.ms + osv). `scannedVersion` is the package version the scan
   evaluated each verdict against (illustrative — the scan was run on axios). */
window.VULN_GROUPS = [
  {
    CanonicalID: "CVE-2026-44494",
    MaxScore: 8.7, ExposureScore: 5, ExposureBucket: "high",
    Affected: true,
    scannedVersion: "axios@1.12.0",
    Members: [
      {
        Record: {
          Source: "ecosyste.ms", OriginalID: "GHSA-35jp-ww65-95wh", Score: 8.7, Severity: "HIGH",
          Published: "2026-05-29T16:04:00Z", Modified: "2026-05-30T19:00:10Z",
          CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
          Title: "axios Vulnerable to Full Man-in-the-Middle via Prototype Pollution Gadget in config.proxy",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.16.0)", NextFix: "1.16.0" },
      },
      {
        Record: {
          Source: "osv", OriginalID: "GHSA-35jp-ww65-95wh", Score: 8.7, Severity: "HIGH",
          Published: "2026-05-29T16:04:00Z", Modified: "2026-06-01T20:14:14Z",
          CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
          Title: "axios Vulnerable to Full Man-in-the-Middle via Prototype Pollution Gadget in config.proxy",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.16.0)", NextFix: "1.16.0" },
      },
    ],
  },
  {
    CanonicalID: "CVE-2026-44495",
    MaxScore: 7, ExposureScore: 4, ExposureBucket: "medium",
    Affected: true,
    scannedVersion: "axios@1.12.0",
    Members: [
      {
        Record: {
          Source: "ecosyste.ms", OriginalID: "GHSA-3g43-6gmg-66jw", Score: 7, Severity: "HIGH",
          Published: "2026-05-29T16:07:31Z", Modified: "2026-05-30T19:00:10Z",
          CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L",
          Title: "axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pollution Gadget in Config Merge",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.15.2)", NextFix: "1.15.2" },
      },
      {
        Record: {
          Source: "osv", OriginalID: "GHSA-3g43-6gmg-66jw", Score: 7, Severity: "HIGH",
          Published: "2026-05-29T16:07:31Z", Modified: "2026-05-29T16:15:52Z",
          CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L",
          Title: "axios Vulnerable to Credential Theft and Response Hijacking via Prototype Pollution Gadget in Config Merge",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.15.2)", NextFix: "1.15.2" },
      },
    ],
  },
  {
    CanonicalID: "CVE-2025-62718",
    MaxScore: 6.3, ExposureScore: 2, ExposureBucket: "low",
    Affected: true,
    scannedVersion: "axios@1.12.0",
    Members: [
      {
        Record: {
          Source: "ecosyste.ms", OriginalID: "GHSA-3p68-rc4w-qgx5", Score: 6.3, Severity: "MODERATE",
          Published: "2026-04-09T17:32:19Z", Modified: "2026-05-23T06:00:49Z",
          CvssVector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N",
          Title: "Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.15.0)", NextFix: "1.15.0" },
      },
      {
        Record: {
          Source: "osv", OriginalID: "GHSA-3p68-rc4w-qgx5", Score: 4.8, Severity: "MODERATE",
          Published: "2026-04-09T17:32:19Z", Modified: "2026-05-08T13:46:43Z",
          CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
          Title: "Axios has a NO_PROXY Hostname Normalization Bypass that Leads to SSRF",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.15.0)", NextFix: "1.15.0" },
      },
    ],
  },
  {
    CanonicalID: "CVE-2026-42044",
    MaxScore: 6.5, ExposureScore: 4, ExposureBucket: "medium",
    Affected: true,
    scannedVersion: "axios@1.12.0",
    Members: [
      {
        Record: {
          Source: "ecosyste.ms", OriginalID: "GHSA-3w6x-2g7m-8v23", Score: 6.5, Severity: "MODERATE",
          Published: "2026-05-05T00:19:33Z", Modified: "2026-05-28T19:01:03Z",
          CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N",
          Title: "Axios: Invisible JSON Response Tampering via Prototype Pollution Gadget in parseReviver",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.15.2)", NextFix: "1.15.2" },
      },
      {
        Record: {
          Source: "osv", OriginalID: "GHSA-3w6x-2g7m-8v23", Score: 6.5, Severity: "MODERATE",
          Published: "2026-05-05T00:19:33Z", Modified: "2026-05-06T15:29:23Z",
          CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N",
          Title: "Axios: Invisible JSON Response Tampering via Prototype Pollution Gadget in parseReviver",
        },
        Verdict: { Matched: true, Reason: "in_affected_range", Range: "[1.0.0, 1.15.2)", NextFix: "1.15.2" },
      },
    ],
  },
  {
    CanonicalID: "CVE-2019-10742",
    MaxScore: 7.5, ExposureScore: 1, ExposureBucket: "low",
    Affected: false,
    scannedVersion: "axios@1.12.0",
    Members: [
      {
        Record: {
          Source: "ecosyste.ms", OriginalID: "GHSA-42xw-2xvc-qx8m", Score: 7.5, Severity: "HIGH",
          Published: "2019-05-29T18:04:45Z", Modified: "2026-06-01T21:12:37Z",
          CvssVector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          Title: "Denial of Service in axios",
        },
        Verdict: { Matched: false, Reason: "not_in_affected_range", Range: "(*, 0.18.0]", NextFix: "0.18.1" },
      },
      {
        Record: {
          Source: "osv", OriginalID: "GHSA-42xw-2xvc-qx8m", Score: 7.5, Severity: "HIGH",
          Published: "2019-05-29T18:04:45Z", Modified: "2026-06-01T21:12:37Z",
          CvssVector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          Title: "Denial of Service in axios",
        },
        Verdict: { Matched: false, Reason: "not_in_affected_range", Range: "(*, 0.18.0]", NextFix: "0.18.1" },
      },
    ],
  },
];
