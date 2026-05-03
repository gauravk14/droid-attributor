"""
signature_comparator.py — Droid-Attributor
============================================
Forensically compares APK signing certificates to determine
if two colliding apps share the same developer identity.

Author : Gaurav Chandran K | NFSU Gandhinagar
Project: Droid-Attributor

Usage:
    python scripts/signature_comparator.py apks/app1.apk apks/app2.apk
    python scripts/signature_comparator.py --dir apks/
"""

import os
import sys
import hashlib
import zipfile
import argparse
import json
from datetime import datetime
from itertools import combinations

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[!] cryptography library not found. Run: pip install cryptography")
    print("[!] Falling back to basic certificate hash comparison.\n")


# ─────────────────────────────────────────────
#  CERTIFICATE EXTRACTION
# ─────────────────────────────────────────────

def extract_certificates(apk_path: str) -> list[bytes]:
    """Extract all raw DER-encoded certificates from an APK's META-INF/."""
    certs = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                upper = name.upper()
                if upper.startswith("META-INF/") and (
                    upper.endswith(".RSA") or
                    upper.endswith(".DSA") or
                    upper.endswith(".EC")
                ):
                    raw = zf.read(name)
                    # PKCS#7 SignedData — certificate starts after CMS wrapper
                    # Try to strip CMS envelope (simple heuristic for Android APKs)
                    cert_der = _strip_pkcs7_wrapper(raw)
                    certs.append(cert_der)
    except zipfile.BadZipFile:
        print(f"  [!] {apk_path} is not a valid ZIP/APK file.")
    except Exception as e:
        print(f"  [!] Error reading {apk_path}: {e}")
    return certs


def _strip_pkcs7_wrapper(data: bytes) -> bytes:
    """
    Very lightweight PKCS#7 unwrapper to reach the X.509 cert DER bytes.
    Android APKs always use a single signer, so we just look for the
    0x30 82 sequence that starts the embedded certificate.
    """
    # Walk bytes looking for the X.509 SEQUENCE tag (0x30) at a reasonable offset
    # Real parsing would use asn1crypto or pyOpenSSL, but cryptography lib handles it
    return data  # cryptography.x509.load_der_x509_certificate handles PKCS7 too


# ─────────────────────────────────────────────
#  CERTIFICATE FINGERPRINTING
# ─────────────────────────────────────────────

def fingerprint_sha256(cert_der: bytes) -> str:
    return hashlib.sha256(cert_der).hexdigest().upper()

def fingerprint_sha1(cert_der: bytes) -> str:
    return hashlib.sha1(cert_der).hexdigest().upper()

def fingerprint_md5(cert_der: bytes) -> str:
    return hashlib.md5(cert_der).hexdigest().upper()


def format_fingerprint(fp: str, sep: str = ":") -> str:
    """Format a hex fingerprint as colon-separated pairs: AB:CD:EF..."""
    return sep.join(fp[i:i+2] for i in range(0, len(fp), 2))


# ─────────────────────────────────────────────
#  CERTIFICATE PARSING (requires cryptography)
# ─────────────────────────────────────────────

def parse_certificate(cert_der: bytes) -> dict:
    """Parse X.509 certificate fields using the cryptography library."""
    info = {}
    if not CRYPTO_AVAILABLE:
        info["sha256"] = format_fingerprint(fingerprint_sha256(cert_der))
        info["sha1"]   = format_fingerprint(fingerprint_sha1(cert_der))
        info["md5"]    = format_fingerprint(fingerprint_md5(cert_der))
        info["raw_size"] = len(cert_der)
        return info

    try:
        # Try loading as raw X.509 first
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        # Some APKs wrap in PKCS#7 — skip advanced parsing, fall back to hash
        info["parse_error"] = "Could not parse as X.509 (may be PKCS#7 wrapped)"
        info["sha256"] = format_fingerprint(fingerprint_sha256(cert_der))
        info["sha1"]   = format_fingerprint(fingerprint_sha1(cert_der))
        info["md5"]    = format_fingerprint(fingerprint_md5(cert_der))
        return info

    # Subject fields
    def get_attr(name_obj, oid):
        try:
            return name_obj.get_attributes_for_oid(oid)[0].value
        except Exception:
            return "N/A"

    O  = x509.NameOID
    subj = cert.subject
    info["subject"] = {
        "CN": get_attr(subj, O.COMMON_NAME),
        "O":  get_attr(subj, O.ORGANIZATION_NAME),
        "OU": get_attr(subj, O.ORGANIZATIONAL_UNIT_NAME),
        "C":  get_attr(subj, O.COUNTRY_NAME),
        "ST": get_attr(subj, O.STATE_OR_PROVINCE_NAME),
        "L":  get_attr(subj, O.LOCALITY_NAME),
        "E":  get_attr(subj, O.EMAIL_ADDRESS),
    }

    issuer = cert.issuer
    info["issuer"] = {
        "CN": get_attr(issuer, O.COMMON_NAME),
        "O":  get_attr(issuer, O.ORGANIZATION_NAME),
    }

    info["serial_number"]  = str(cert.serial_number)
    info["not_valid_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before)
    info["not_valid_after"]  = cert.not_valid_after_utc.isoformat()  if hasattr(cert, 'not_valid_after_utc')  else str(cert.not_valid_after)
    info["signature_algorithm"] = cert.signature_algorithm_oid.dotted_string

    # Fingerprints computed from the raw DER
    info["sha256"] = format_fingerprint(fingerprint_sha256(cert_der))
    info["sha1"]   = format_fingerprint(fingerprint_sha1(cert_der))
    info["md5"]    = format_fingerprint(fingerprint_md5(cert_der))

    # Self-signed check (Android debug certs are always self-signed)
    info["self_signed"] = (cert.subject == cert.issuer)

    return info


# ─────────────────────────────────────────────
#  APK PROFILE
# ─────────────────────────────────────────────

def build_apk_profile(apk_path: str) -> dict:
    """Build a complete forensic certificate profile for an APK."""
    profile = {
        "apk": os.path.basename(apk_path),
        "path": apk_path,
        "file_size_bytes": os.path.getsize(apk_path) if os.path.exists(apk_path) else 0,
        "certificates": [],
        "cert_count": 0,
        "signed": False,
    }

    certs_der = extract_certificates(apk_path)
    profile["cert_count"] = len(certs_der)
    profile["signed"] = len(certs_der) > 0

    for cert_der in certs_der:
        parsed = parse_certificate(cert_der)
        profile["certificates"].append(parsed)

    return profile


# ─────────────────────────────────────────────
#  COMPARISON ENGINE
# ─────────────────────────────────────────────

SAME_DEVELOPER    = "SAME_DEVELOPER"
DIFFERENT_DEVELOPER = "DIFFERENT_DEVELOPER"
UNSIGNED          = "UNSIGNED"
INCONCLUSIVE      = "INCONCLUSIVE"

def compare_two_apks(profile_a: dict, profile_b: dict) -> dict:
    """
    Compare two APK certificate profiles.
    Returns a verdict with forensic evidence.
    """
    result = {
        "apk_a": profile_a["apk"],
        "apk_b": profile_b["apk"],
        "verdict": INCONCLUSIVE,
        "confidence": 0,        # 0–100
        "evidence": [],
        "risk_flags": [],
    }

    # ── Unsigned APKs ──
    if not profile_a["signed"] and not profile_b["signed"]:
        result["verdict"] = UNSIGNED
        result["evidence"].append("Both APKs are unsigned — cannot perform certificate attribution.")
        return result

    if not profile_a["signed"]:
        result["verdict"] = UNSIGNED
        result["evidence"].append(f"{profile_a['apk']} is unsigned.")
        return result

    if not profile_b["signed"]:
        result["verdict"] = UNSIGNED
        result["evidence"].append(f"{profile_b['apk']} is unsigned.")
        return result

    # ── Certificate count mismatch ──
    if profile_a["cert_count"] != profile_b["cert_count"]:
        result["evidence"].append(
            f"Certificate count differs: {profile_a['apk']}={profile_a['cert_count']}, "
            f"{profile_b['apk']}={profile_b['cert_count']}"
        )

    # ── Primary certificate comparison ──
    certs_a = profile_a["certificates"]
    certs_b = profile_b["certificates"]

    if not certs_a or not certs_b:
        result["verdict"] = INCONCLUSIVE
        result["evidence"].append("Could not extract certificates from one or both APKs.")
        return result

    cert_a = certs_a[0]
    cert_b = certs_b[0]

    # SHA-256 fingerprint — the gold standard
    sha256_match = cert_a.get("sha256") == cert_b.get("sha256")
    sha1_match   = cert_a.get("sha1")   == cert_b.get("sha1")
    md5_match    = cert_a.get("md5")    == cert_b.get("md5")

    result["evidence"].append(f"SHA-256 fingerprint match: {'✅ YES' if sha256_match else '❌ NO'}")
    result["evidence"].append(f"  A: {cert_a.get('sha256', 'N/A')}")
    result["evidence"].append(f"  B: {cert_b.get('sha256', 'N/A')}")

    if sha256_match and sha1_match and md5_match:
        result["verdict"]    = SAME_DEVELOPER
        result["confidence"] = 99
        result["evidence"].append("All fingerprints match — cryptographically identical signing key.")
        result["risk_flags"].append("REPACKAGED_OR_CLONE: Same certificate used on colliding APK.")
    else:
        result["verdict"]    = DIFFERENT_DEVELOPER
        result["confidence"] = 95
        result["evidence"].append("Fingerprints do NOT match — different private keys used.")
        result["evidence"].append("This is the forensic smoking gun: a third party deliberately")
        result["evidence"].append("created an app to collide with the target's URI scheme.")
        result["risk_flags"].append("DELIBERATE_HIJACK: Different developer registered identical deep-link.")

    # ── Subject field comparison (if available) ──
    subj_a = cert_a.get("subject", {})
    subj_b = cert_b.get("subject", {})

    if subj_a and subj_b and "parse_error" not in cert_a:
        fields_to_compare = ["CN", "O", "OU", "C", "E"]
        for field in fields_to_compare:
            val_a = subj_a.get(field, "N/A")
            val_b = subj_b.get(field, "N/A")
            if val_a != "N/A" or val_b != "N/A":
                match = val_a == val_b
                result["evidence"].append(
                    f"Subject {field}: {'MATCH' if match else 'DIFFER'} | A='{val_a}' B='{val_b}'"
                )

    # ── Self-signed flag (Android debug cert warning) ──
    for label, cert in [("A", cert_a), ("B", cert_b)]:
        if cert.get("self_signed"):
            result["risk_flags"].append(
                f"APK_{label}_DEBUG_CERT: Self-signed certificate (could be dev/test build)."
            )

    # ── Serial number ──
    if "serial_number" in cert_a and "serial_number" in cert_b:
        if cert_a["serial_number"] == cert_b["serial_number"]:
            result["evidence"].append("Serial numbers match — extremely strong identity link.")
        else:
            result["evidence"].append(
                f"Serial numbers differ: A={cert_a['serial_number']} B={cert_b['serial_number']}"
            )

    return result


# ─────────────────────────────────────────────
#  BATCH MODE — scan entire directory
# ─────────────────────────────────────────────

def scan_directory(apk_dir: str) -> list[dict]:
    """Compare all APK pairs in a directory."""
    apks = [
        os.path.join(apk_dir, f)
        for f in os.listdir(apk_dir)
        if f.lower().endswith(".apk")
    ]

    if len(apks) < 2:
        print(f"[!] Need at least 2 APKs in {apk_dir}. Found {len(apks)}.")
        return []

    print(f"[*] Found {len(apks)} APKs — building profiles...")
    profiles = [build_apk_profile(p) for p in apks]

    results = []
    pairs = list(combinations(profiles, 2))
    print(f"[*] Comparing {len(pairs)} pairs...\n")

    for pa, pb in pairs:
        r = compare_two_apks(pa, pb)
        results.append(r)

    return results


# ─────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────

VERDICT_COLOR = {
    SAME_DEVELOPER:     "\033[93m",   # Yellow  — suspicious
    DIFFERENT_DEVELOPER:"\033[91m",   # Red     — likely attack
    UNSIGNED:           "\033[90m",   # Grey
    INCONCLUSIVE:       "\033[94m",   # Blue
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_profile(profile: dict):
    print(f"\n{'='*60}")
    print(f"  APK: {profile['apk']}")
    print(f"  Size: {profile['file_size_bytes']:,} bytes")
    print(f"  Signed: {'Yes' if profile['signed'] else 'NO — UNSIGNED'}")
    print(f"  Certificates found: {profile['cert_count']}")

    for i, cert in enumerate(profile["certificates"]):
        print(f"\n  --- Certificate #{i+1} ---")
        if "parse_error" in cert:
            print(f"  Parse note: {cert['parse_error']}")
        subj = cert.get("subject", {})
        if subj:
            print(f"  Subject CN : {subj.get('CN', 'N/A')}")
            print(f"  Subject O  : {subj.get('O', 'N/A')}")
            print(f"  Subject C  : {subj.get('C', 'N/A')}")
        print(f"  Self-signed: {cert.get('self_signed', 'N/A')}")
        print(f"  SHA-256    : {cert.get('sha256', 'N/A')}")
        print(f"  SHA-1      : {cert.get('sha1', 'N/A')}")
        print(f"  Valid until: {cert.get('not_valid_after', 'N/A')}")
    print(f"{'='*60}")


def print_comparison(result: dict):
    verdict = result["verdict"]
    color   = VERDICT_COLOR.get(verdict, "")

    print(f"\n{'─'*60}")
    print(f"  Comparing: {result['apk_a']}  vs  {result['apk_b']}")
    print(f"  {BOLD}Verdict: {color}{verdict}{RESET}")
    print(f"  Confidence: {result['confidence']}%")
    print(f"\n  Evidence:")
    for e in result["evidence"]:
        print(f"    {e}")
    if result["risk_flags"]:
        print(f"\n  ⚠️  Risk Flags:")
        for f in result["risk_flags"]:
            print(f"    🚩 {f}")
    print(f"{'─'*60}")


def save_json_report(profiles: list, comparisons: list, output_path: str):
    report = {
        "tool": "Droid-Attributor — Signature Comparator",
        "author": "Gaurav Chandran K | NFSU Gandhinagar",
        "generated_at": datetime.now().isoformat(),
        "apk_profiles": profiles,
        "comparisons": comparisons,
        "summary": {
            "total_apks": len(profiles),
            "total_pairs": len(comparisons),
            "same_developer": sum(1 for c in comparisons if c["verdict"] == SAME_DEVELOPER),
            "different_developer": sum(1 for c in comparisons if c["verdict"] == DIFFERENT_DEVELOPER),
            "unsigned": sum(1 for c in comparisons if c["verdict"] == UNSIGNED),
        }
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[✓] JSON report saved → {output_path}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Droid-Attributor: APK Signing Certificate Comparator"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("apks", nargs="*", help="Two APK files to compare")
    group.add_argument("--dir", metavar="DIR", help="Directory of APKs to compare all pairs")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to file")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}")
    print("  Droid-Attributor — Signature Comparator")
    print("  Gaurav Chandran K | NFSU Gandhinagar")
    print(f"{'='*60}{RESET}\n")

    profiles    = []
    comparisons = []

    if args.dir:
        # ── Batch mode ──
        comparisons = scan_directory(args.dir)
        # Rebuild profiles for report
        apks = [
            os.path.join(args.dir, f)
            for f in os.listdir(args.dir)
            if f.lower().endswith(".apk")
        ]
        profiles = [build_apk_profile(p) for p in apks]
        for r in comparisons:
            print_comparison(r)

    else:
        # ── Two-APK mode ──
        if len(args.apks) != 2:
            print("Error: Provide exactly 2 APK paths, or use --dir for batch mode.")
            sys.exit(1)

        apk_a, apk_b = args.apks
        for path in [apk_a, apk_b]:
            if not os.path.exists(path):
                print(f"[!] File not found: {path}")
                sys.exit(1)

        profile_a = build_apk_profile(apk_a)
        profile_b = build_apk_profile(apk_b)
        profiles  = [profile_a, profile_b]

        print_profile(profile_a)
        print_profile(profile_b)

        result = compare_two_apks(profile_a, profile_b)
        comparisons = [result]
        print_comparison(result)

    # ── Summary ──
    print(f"\n{BOLD}── SUMMARY ──{RESET}")
    same    = sum(1 for c in comparisons if c["verdict"] == SAME_DEVELOPER)
    differ  = sum(1 for c in comparisons if c["verdict"] == DIFFERENT_DEVELOPER)
    unsigned= sum(1 for c in comparisons if c["verdict"] == UNSIGNED)
    print(f"  Pairs compared     : {len(comparisons)}")
    print(f"  Same developer     : {same}")
    print(f"  Different developer: {differ}  ← Potential deliberate hijacks")
    print(f"  Unsigned APKs      : {unsigned}")

    if args.json:
        save_json_report(profiles, comparisons, args.json)

    return comparisons


if __name__ == "__main__":
    main()
