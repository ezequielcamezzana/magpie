/* Sample advisory data for the kit. Illustrative only. */
window.ADVISORIES = [
  { id:"CVE-2026-0142", name:"Heap overflow in certificate parser", pkg:"openssl", versions:"≤ 3.2.1", fixed:"3.2.2", sev:"high", cvss:"8.1", date:"2026-05-28", source:"NVD",
    summary:"A heap-based buffer overflow in the X.509 certificate parser allows a remote attacker to crash the process or potentially execute code via a crafted certificate chain." },
  { id:"CVE-2026-0098", name:"Prototype pollution in deep-merge", pkg:"lodash", versions:"< 4.17.22", fixed:"4.17.22", sev:"critical", cvss:"9.8", date:"2026-05-22", source:"GHSA",
    summary:"Improper key sanitization in the recursive merge routine permits attacker-controlled input to pollute Object.prototype, leading to denial of service and, in some configurations, remote code execution." },
  { id:"CVE-2026-0077", name:"Timing side-channel in HMAC compare", pkg:"jsonwebtoken", versions:"9.0.0 – 9.0.3", fixed:"9.0.4", sev:"medium", cvss:"5.9", date:"2026-05-19", source:"NVD",
    summary:"Signature verification uses a non-constant-time comparison, leaking timing information that may help an attacker forge tokens over many requests." },
  { id:"CVE-2026-0061", name:"ReDoS in URL template matcher", pkg:"path-to-regexp", versions:"< 6.3.0", fixed:"6.3.0", sev:"high", cvss:"7.5", date:"2026-05-15", source:"GHSA",
    summary:"A catastrophic backtracking regular expression allows a crafted path to consume CPU for seconds per request, enabling denial of service." },
  { id:"CVE-2026-0044", name:"Open redirect in OAuth callback", pkg:"passport-oauth2", versions:"< 1.8.1", fixed:"1.8.1", sev:"medium", cvss:"6.1", date:"2026-05-11", source:"NVD",
    summary:"The callback handler does not validate the return URL against an allowlist, permitting an attacker to redirect authenticated users to an arbitrary site." },
  { id:"CVE-2026-0031", name:"Improper cert chain validation", pkg:"node-fetch", versions:"< 3.3.3", fixed:"3.3.3", sev:"critical", cvss:"9.1", date:"2026-05-06", source:"GHSA",
    summary:"Under proxy configurations, intermediate certificate validation can be skipped, allowing a man-in-the-middle attacker to present a forged certificate." },
  { id:"CVE-2026-0019", name:"Integer overflow in image decoder", pkg:"sharp", versions:"< 0.33.4", fixed:"0.33.4", sev:"high", cvss:"7.8", date:"2026-04-30", source:"NVD",
    summary:"An integer overflow when computing buffer sizes for malformed WebP input can lead to an out-of-bounds write." },
  { id:"CVE-2026-0007", name:"Insufficient entropy in token id", pkg:"nanoid", versions:"< 5.0.7", fixed:"5.0.7", sev:"low", cvss:"3.7", date:"2026-04-24", source:"GHSA",
    summary:"Under a misconfigured custom alphabet, generated identifiers may have reduced entropy, marginally increasing collision and guess probability." },
];
