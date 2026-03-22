from androguard.misc import AnalyzeAPK
import os
import json
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

APK_DIR = "apks/"
scheme_registry = defaultdict(list)
app_data = []

print(Fore.CYAN + "\n[*] Droid-Attributor — Collision Detector")
print(Fore.CYAN + "=" * 50)

# Scan all APKs in the apks/ folder
for apk_file in os.listdir(APK_DIR):
    if not apk_file.endswith(".apk"):
        continue

    path = os.path.join(APK_DIR, apk_file)
    print(f"\n[*] Scanning: {apk_file}")

    try:
        apk, d, dx = AnalyzeAPK(path)
        package = apk.get_package()
        permissions = apk.get_permissions()
        schemes_found = []

        for activity in apk.get_activities():
            filters = apk.get_intent_filters("activity", activity)
            if not filters:
                continue
            data = filters.get("data", [])
            for item in data:
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
            "permissions": permissions,
            "schemes": schemes_found
        })

        if schemes_found:
            print(Fore.YELLOW + f"  [!] Custom schemes found in {package}:")
            for s in schemes_found:
                print(f"      scheme://{s['scheme']} → {s['activity']}")
        else:
            print(Fore.GREEN + f"  [+] No custom schemes in {package}")

    except Exception as e:
        print(Fore.RED + f"  [ERROR] {apk_file}: {e}")

# Detect collisions
print(Fore.CYAN + "\n" + "=" * 50)
print(Fore.CYAN + "[*] COLLISION REPORT")
print(Fore.CYAN + "=" * 50)

collisions_found = False
for scheme, claimants in scheme_registry.items():
    if len(claimants) > 1:
        collisions_found = True
        print(Fore.RED + f"\n[!!] COLLISION DETECTED — scheme: '{scheme}'")
        for c in claimants:
            print(f"     → {c['package']} ({c['apk_file']})")
            print(f"       Activity: {c['activity']}")

if not collisions_found:
    print(Fore.GREEN + "\n[+] No collisions found across scanned APKs.")
    print("[*] Add more APKs to apks/ folder to test collisions.")

# Save results
with open("reports/collision_report.json", "w") as f:
    json.dump({
        "apps_scanned": len(app_data),
        "scheme_registry": scheme_registry,
        "app_data": app_data
    }, f, indent=2)

print(Fore.CYAN + "\n[*] Report saved to reports/collision_report.json")
