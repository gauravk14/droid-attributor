import os
import sys
import json
import time
import argparse
from datetime import datetime
from colorama import Fore, init
from androguard.misc import AnalyzeAPK
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from signature_comparator import build_apk_profile, compare_two_apks, DIFFERENT_DEVELOPER, SAME_DEVELOPER

init(autoreset=True)


def print_banner():
    print(Fore.CYAN + """
██████╗ ██████╗  ██████╗ ██╗██████╗ 
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
██║  ██║██████╔╝██║   ██║██║██║  ██║
██║  ██║██╔══██╗██║   ██║██║██║  ██║
██████╔╝██║  ██║╚██████╔╝██║██████╔╝
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ 
    ATTRIBUTOR — Android Deep-Link Forensics
    v2.1 | Gaurav Chandran K | NFSU Gandhinagar
    """)


# ── PHASE 1 ───────────────────────────────────────────────────────────────────
def phase1_collect(apk_dir):
    print(Fore.CYAN + f"\n[PHASE 1] Collecting APKs from: {apk_dir}")

    if not os.path.isdir(apk_dir):
        print(Fore.RED + f"[-] Directory not found: {apk_dir}")
        sys.exit(1)

    # Recursively find all APKs (covers apks/ and apks/dataset/)
    apks = []
    for root, _, files in os.walk(apk_dir):
        for f in files:
            if f.endswith(".apk"):
                apks.append(os.path.relpath(os.path.join(root, f), apk_dir))

    if not apks:
        print(Fore.RED + f"[-] No APK files found in {apk_dir}")
        sys.exit(1)

    print(f"[+] Found {len(apks)} APK(s):")
    for a in apks:
        full = os.path.join(apk_dir, a)
        size = os.path.getsize(full)
        print(f"    → {a} ({size // 1024} KB)")

    return apks


# ── PHASE 2 ───────────────────────────────────────────────────────────────────
def phase2_static(apks, apk_dir):
    print(Fore.CYAN + "\n[PHASE 2] Static Analysis + Collision Detection...")
    scheme_registry = defaultdict(list)
    app_data = []
    errors = []

    for apk_file in apks:
        path = os.path.join(apk_dir, apk_file)
        try:
            apk, d, dx = AnalyzeAPK(path)
            package = apk.get_package()
            permissions = apk.get_permissions()
            schemes_found = []

            for activity in apk.get_activities():
                filters = apk.get_intent_filters("activity", activity)
                if not filters:
                    continue
                for item in filters.get("data", []):
                    scheme = item.get("scheme")
                    if scheme and scheme not in ["http", "https"]:
                        schemes_found.append({
                            "scheme":   scheme,
                            "host":     item.get("host", ""),
                            "activity": activity
                        })
                        scheme_registry[scheme].append({
                            "package":  package,
                            "activity": activity,
                            "apk_file": apk_file
                        })

            app_data.append({
                "package":     package,
                "apk_file":    apk_file,
                "permissions": list(permissions),
                "schemes":     schemes_found
            })

            if schemes_found:
                print(Fore.YELLOW + f"[!] {package}: {[s['scheme'] for s in schemes_found]}")
            else:
                print(Fore.GREEN + f"[+] {package}: no custom schemes")

        except Exception as e:
            print(Fore.RED + f"[-] Error scanning {apk_file}: {e}")
            errors.append({"apk": apk_file, "error": str(e)})

    collisions = {s: v for s, v in scheme_registry.items() if len(v) > 1}

    if collisions:
        print(Fore.RED + f"\n[!!] {len(collisions)} COLLISION(S) DETECTED!")
        for scheme, claimants in collisions.items():
            print(Fore.RED + f"    scheme: '{scheme}'")
            for c in claimants:
                print(f"      → {c['package']}")
    else:
        print(Fore.GREEN + "\n[+] No scheme collisions found among scanned APKs")

    if errors:
        print(Fore.YELLOW + f"\n[!] {len(errors)} APK(s) could not be parsed (may be obfuscated/corrupt)")

    return app_data, collisions, errors


# ── PHASE 3 ───────────────────────────────────────────────────────────────────
def phase3_signature(collisions, apk_dir):
    print(Fore.CYAN + "\n[PHASE 3] Signature Certificate Comparison...")
    sig_results = {}

    if not collisions:
        print(Fore.GREEN + "[+] No collisions to compare signatures for.")
        return sig_results

    for scheme, claimants in collisions.items():
        print(f"\n[*] Certificate comparison for scheme: '{scheme}'")
        profiles = []
        for claimant in claimants:
            apk_path = os.path.join(apk_dir, claimant["apk_file"])
            profile  = build_apk_profile(apk_path)
            profiles.append((claimant, profile))

        for i in range(len(profiles)):
            for j in range(i + 1, len(profiles)):
                claimant_a, profile_a = profiles[i]
                claimant_b, profile_b = profiles[j]
                result  = compare_two_apks(profile_a, profile_b)
                verdict = result["verdict"]

                if verdict == DIFFERENT_DEVELOPER:
                    color = Fore.RED
                    tag   = "🚩 DELIBERATE HIJACK — Different signing certificates"
                elif verdict == SAME_DEVELOPER:
                    color = Fore.YELLOW
                    tag   = "⚠️  SAME DEVELOPER — Possible repackage/clone"
                else:
                    color = Fore.WHITE
                    tag   = f"ℹ️  {verdict}"

                print(color + f"  {profile_a['apk']} vs {profile_b['apk']}")
                print(color + f"  → {tag} (Confidence: {result['confidence']}%)")

                certs_a = profile_a.get("certificates", [])
                certs_b = profile_b.get("certificates", [])
                if certs_a and certs_b:
                    print(f"    SHA-256 A: {certs_a[0].get('sha256', 'N/A')}")
                    print(f"    SHA-256 B: {certs_b[0].get('sha256', 'N/A')}")

                key = f"{profile_a['apk']}|{profile_b['apk']}"
                sig_results[key] = {
                    "scheme":     scheme,
                    "verdict":    verdict,
                    "confidence": result["confidence"],
                    "risk_flags": result["risk_flags"],
                    "sha256_a":   certs_a[0].get("sha256") if certs_a else None,
                    "sha256_b":   certs_b[0].get("sha256") if certs_b else None,
                }

    deliberate = sum(1 for r in sig_results.values() if r["verdict"] == DIFFERENT_DEVELOPER)
    print(Fore.RED + f"\n[!!] {deliberate} pair(s) confirmed as DELIBERATE HIJACK via certificate mismatch.")
    return sig_results


# ── PHASE 4 ───────────────────────────────────────────────────────────────────
def phase4_attribution(app_data, collisions, sig_results, apk_dir):
    print(Fore.CYAN + "\n[PHASE 4] Forensic Attribution (all APKs)...")
    verdicts = {}

    # Score ALL APKs, not just those in collisions
    for app in app_data:
        pkg      = app["package"]
        apk_file = app["apk_file"]
        score    = 0
        indicators = []

        try:
            apk, d, dx = AnalyzeAPK(os.path.join(apk_dir, apk_file))
            perms = apk.get_permissions()

            # Dangerous permissions
            dangerous = [p for p in perms if any(x in p for x in
                ["INTERNET", "READ_CONTACTS", "READ_SMS",
                 "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
                 "READ_CALL_LOG", "SEND_SMS", "CAMERA"])]
            score += len(dangerous) * 10
            if dangerous:
                indicators.append(f"Dangerous permissions: {dangerous}")

            # Network API usage
            net_hits = 0
            for cls in dx.get_classes():
                for method in cls.get_methods():
                    for _, call, _ in method.get_xref_to():
                        if any(x in str(call.class_name) for x in
                               ["HttpURLConnection", "OkHttp", "Volley", "Socket"]):
                            net_hits += 1
            if net_hits:
                score += 30
                indicators.append(f"Network API calls detected: {net_hits}")

            # Custom URI scheme (deep-link) present
            if app.get("schemes"):
                score += 15
                indicators.append(f"Custom URI schemes: {[s['scheme'] for s in app['schemes']]}")

            # Part of a collision
            in_collision = any(
                any(c["apk_file"] == apk_file for c in claimants)
                for claimants in collisions.values()
            )
            if in_collision:
                score += 15
                indicators.append("Involved in URI scheme collision")

            # Certificate mismatch (signature comparator boost)
            for key, sig in sig_results.items():
                if apk_file in key and sig["verdict"] == DIFFERENT_DEVELOPER:
                    score += 20
                    indicators.append("Certificate mismatch — different developer confirmed")
                    break

            score   = min(score, 100)
            verdict = "MALICIOUS"   if score >= 60 else \
                      "SUSPICIOUS"  if score >= 30 else "LOW RISK"
            color   = Fore.RED      if score >= 60 else \
                      Fore.YELLOW   if score >= 30 else Fore.GREEN

            print(color + f"  [{score:3d}/100] {verdict:10s} — {pkg}")
            for ind in indicators:
                print(f"              ↳ {ind}")

            verdicts[pkg] = {
                "apk_file":   apk_file,
                "score":      score,
                "verdict":    verdict,
                "indicators": indicators
            }

        except Exception as e:
            print(Fore.RED + f"  Error attributing {pkg}: {e}")

    return verdicts


# ── PHASE 5 ───────────────────────────────────────────────────────────────────
def phase5_report(app_data, collisions, sig_results, verdicts, errors, apk_dir):
    print(Fore.CYAN + "\n[PHASE 5] Generating Report...")

    report = {
        "title":         "Droid-Attributor Forensic Report",
        "version":       "2.1",
        "generated":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "investigator":  "Gaurav Chandran K",
        "institution":   "National Forensic Sciences University, Gandhinagar",
        "apk_directory": apk_dir,
        "stats": {
            "apks_scanned":       len(app_data),
            "parse_errors":       len(errors),
            "collisions_found":   len(collisions),
            "deliberate_hijacks": sum(1 for r in sig_results.values()
                                      if r["verdict"] == DIFFERENT_DEVELOPER),
            "malicious":          sum(1 for v in verdicts.values()
                                      if v["verdict"] == "MALICIOUS"),
            "suspicious":         sum(1 for v in verdicts.values()
                                      if v["verdict"] == "SUSPICIOUS"),
            "low_risk":           sum(1 for v in verdicts.values()
                                      if v["verdict"] == "LOW RISK"),
        },
        "collisions":            dict(collisions),
        "signature_comparison":  sig_results,
        "verdicts":              verdicts,
        "parse_errors":          errors,
    }

    os.makedirs("reports", exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"reports/full_pipeline_report_{ts}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    s = report["stats"]
    print(Fore.CYAN + "\n" + "=" * 55)
    print(Fore.CYAN + "  PIPELINE SUMMARY — Droid-Attributor v2.1")
    print(Fore.CYAN + "=" * 55)
    print(f"\n  APKs scanned       : {s['apks_scanned']}")
    print(f"  Parse errors       : {s['parse_errors']}")
    print(f"  Collisions found   : {s['collisions_found']}")
    print(Fore.RED    + f"  Deliberate hijacks : {s['deliberate_hijacks']}  ← cert mismatch")
    print(Fore.RED    + f"  Malicious apps     : {s['malicious']}")
    print(Fore.YELLOW + f"  Suspicious apps    : {s['suspicious']}")
    print(Fore.GREEN  + f"  Low risk apps      : {s['low_risk']}")
    print(Fore.GREEN  + f"\n[+] Report saved: {path}")
    return path


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Droid-Attributor Pipeline")
    parser.add_argument(
        "--input", default="apks/",
        help="Directory containing APKs to scan (default: apks/). "
             "Use apks/dataset/ for downloaded malware samples."
    )
    args = parser.parse_args()

    start = time.time()
    print_banner()

    apk_dir                          = args.input.rstrip("/") + "/"
    apks                             = phase1_collect(apk_dir)
    app_data, collisions, errors     = phase2_static(apks, apk_dir)
    sig_results                      = phase3_signature(collisions, apk_dir)
    verdicts                         = phase4_attribution(app_data, collisions, sig_results, apk_dir)
    report_path                      = phase5_report(app_data, collisions, sig_results, verdicts, errors, apk_dir)

    elapsed = time.time() - start
    print(Fore.CYAN + f"\n[*] Pipeline completed in {elapsed:.1f}s")
    print(Fore.CYAN + f"[*] Full report: {report_path}")
