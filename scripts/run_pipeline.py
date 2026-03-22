import os
import sys
import json
import time
from datetime import datetime
from colorama import Fore, init
from androguard.misc import AnalyzeAPK
from collections import defaultdict

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
    """)

def phase1_collect(apk_dir="apks/"):
    print(Fore.CYAN + "\n[PHASE 1] Collecting APKs...")
    apks = [f for f in os.listdir(apk_dir) if f.endswith(".apk")]
    print(f"[+] Found {len(apks)} APKs in {apk_dir}")
    for a in apks:
        size = os.path.getsize(f"{apk_dir}{a}")
        print(f"    → {a} ({size//1024}KB)")
    return apks

def phase2_static(apks, apk_dir="apks/"):
    print(Fore.CYAN + "\n[PHASE 2] Static Analysis + Collision Detection...")
    scheme_registry = defaultdict(list)
    app_data = []

    for apk_file in apks:
        path = f"{apk_dir}{apk_file}"
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
                            "scheme": scheme,
                            "host": item.get("host", ""),
                            "activity": activity
                        })
                        scheme_registry[scheme].append({
                            "package": package,
                            "activity": activity,
                            "apk_file": apk_file
                        })

            app_data.append({
                "package": package,
                "apk_file": apk_file,
                "permissions": list(permissions),
                "schemes": schemes_found
            })

            if schemes_found:
                print(Fore.YELLOW + f"[!] {package}: {[s['scheme'] for s in schemes_found]}")
            else:
                print(Fore.GREEN + f"[+] {package}: no custom schemes")

        except Exception as e:
            print(Fore.RED + f"[-] Error scanning {apk_file}: {e}")

    # Find collisions
    collisions = {s: v for s, v in scheme_registry.items() if len(v) > 1}

    if collisions:
        print(Fore.RED + f"\n[!!] {len(collisions)} COLLISION(S) DETECTED!")
        for scheme, claimants in collisions.items():
            print(Fore.RED + f"    scheme: '{scheme}'")
            for c in claimants:
                print(f"      → {c['package']}")
    else:
        print(Fore.GREEN + "\n[+] No collisions found")

    return app_data, collisions

def phase4_attribution(collisions, apk_dir="apks/"):
    print(Fore.CYAN + "\n[PHASE 4] Forensic Attribution...")
    verdicts = {}

    for scheme, claimants in collisions.items():
        print(f"\n[*] Analyzing collision: '{scheme}'")
        for claimant in claimants:
            pkg = claimant["package"]
            apk_file = claimant["apk_file"]
            score = 0
            indicators = []

            try:
                apk, d, dx = AnalyzeAPK(f"{apk_dir}{apk_file}")
                perms = apk.get_permissions()

                # Score dangerous permissions
                dangerous = [p for p in perms if any(x in p for x in
                    ["INTERNET", "READ_CONTACTS", "READ_SMS",
                     "RECORD_AUDIO", "ACCESS_FINE_LOCATION"])]
                score += len(dangerous) * 10
                if dangerous:
                    indicators.append(f"Dangerous permissions: {len(dangerous)}")

                # Score network API usage
                net_hits = 0
                for cls in dx.get_classes():
                    for method in cls.get_methods():
                        for _, call, _ in method.get_xref_to():
                            if any(x in str(call.class_name) for x in
                                   ["HttpURLConnection", "OkHttp", "Volley"]):
                                net_hits += 1
                if net_hits:
                    score += 30
                    indicators.append(f"Network API calls: {net_hits}")

                verdict = "MALICIOUS" if score >= 50 else \
                          "SUSPICIOUS" if score >= 25 else "LOW RISK"
                color = Fore.RED if score >= 50 else \
                        Fore.YELLOW if score >= 25 else Fore.GREEN

                print(color + f"  {pkg}: {score}/100 — {verdict}")
                verdicts[pkg] = {
                    "score": score,
                    "verdict": verdict,
                    "indicators": indicators
                }

            except Exception as e:
                print(Fore.RED + f"  Error: {pkg} — {e}")

    return verdicts

def phase5_report(app_data, collisions, verdicts):
    print(Fore.CYAN + "\n[PHASE 5] Generating Report...")

    report = {
        "title": "Droid-Attributor Forensic Report",
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "investigator": "Gaurav Chandran K",
        "stats": {
            "apks_scanned": len(app_data),
            "collisions_found": len(collisions),
            "malicious_confirmed": sum(
                1 for v in verdicts.values()
                if v["verdict"] == "MALICIOUS"
            )
        },
        "collisions": dict(collisions),
        "verdicts": verdicts
    }

    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"reports/full_pipeline_report_{ts}.json"

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print(Fore.CYAN + "\n" + "="*55)
    print(Fore.CYAN + "  PIPELINE SUMMARY")
    print(Fore.CYAN + "="*55)
    print(f"\n  APKs scanned     : {report['stats']['apks_scanned']}")
    print(f"  Collisions found : {report['stats']['collisions_found']}")
    print(f"  Malicious apps   : {report['stats']['malicious_confirmed']}")
    print(Fore.GREEN + f"\n[+] Report saved: {path}")

    return path

# ── MAIN PIPELINE ──
if __name__ == "__main__":
    start = time.time()
    print_banner()

    apks        = phase1_collect()
    app_data, collisions = phase2_static(apks)
    verdicts    = phase4_attribution(collisions)
    report_path = phase5_report(app_data, collisions, verdicts)

    elapsed = time.time() - start
    print(Fore.CYAN + f"\n[*] Pipeline completed in {elapsed:.1f}s")
    print(Fore.CYAN + f"[*] Full report: {report_path}")
