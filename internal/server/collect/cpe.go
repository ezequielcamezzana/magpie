package collect

import "strings"

// NVD records and resolved CPEs identify a product by its CPE 2.3 string. NVD
// VulnRecords carry the full string in AffectedPackage (so target_sw — part 10
// — survives in the flat VulnRecord), while ResolvedCPE.CPE and the cache keys
// use the short cpe:2.3:a:vendor:product form.

// ShortCPE truncates a CPE 2.3 string to cpe:2.3:a:vendor:product. A string
// already in short form is returned unchanged.
func ShortCPE(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return cpe
	}
	return strings.Join(parts[:5], ":")
}

// CPEParts pulls the meaningful slots out of a CPE 2.3 string: vendor (part 3),
// product (part 4) and target_sw (part 10). Missing slots come back "".
func CPEParts(cpe string) (vendor, product, targetSw string) {
	parts := strings.Split(cpe, ":")
	if len(parts) > 3 {
		vendor = parts[3]
	}
	if len(parts) > 4 {
		product = parts[4]
	}
	if len(parts) > 10 && parts[10] != "*" {
		targetSw = parts[10]
	}
	return vendor, product, targetSw
}

// BuildCPE assembles a CPE 2.3 application string from vendor/product/target_sw,
// leaving the other slots wildcarded. Inverse of CPEParts.
func BuildCPE(vendor, product, targetSw string) string {
	if targetSw == "" {
		targetSw = "*"
	}
	return "cpe:2.3:a:" + vendor + ":" + product + ":*:*:*:*:*:" + targetSw + ":*:*"
}

// NVDCVEKey is the per-CVE cache key for NVD's CPE configurations (CPER's
// FetchCVE cache). Shared across packages — a CVE's config is package-independent.
func NVDCVEKey(cve string) string { return "cve:" + cve }

// NVDCPEKey is the per-CPE cache key for NVD's by-CPE query (stage 4). It is
// also the key the package assembly reads NVD records from.
func NVDCPEKey(cpe string) string { return "cpe:" + ShortCPE(cpe) }
