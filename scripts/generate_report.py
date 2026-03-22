import json
import os
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

report = {
    "title": "Droid-Attributor Forensic Attribution Report",
    "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "investigator": "Gaurav Chandran K",
    "case_id": "DA-2026-001",

    "executive_summary": (
        "Two Android applications were found claiming identical "
        "custom URI scheme 'insecureshop://'. Dynamic analysis confirmed "
        "that both applications can intercept sensitive authentication tokens. "
        "Forensic attribution analysis determined the collision is DELIBERATE "
        "and not a developer oversight."
    ),

    "phase2_static": {
        "apks_scanned": 2,
        "collision_detected": True,
        "scheme": "insecureshop://",
        "legitimate_app": {
            "package": "com.insecureshop",
            "activity": "com.insecureshop.WebViewActivity",
            "apk": "InsecureShop.apk"
        },
        "malicious_app": {
            "package": "com.evil.hijacke",
            "activity": "com.evil.hijacke.WebViewActivity",
            "apk": "evil_hijacker.apk"
        }
    },

    "phase3_dynamic": {
        "tool": "Drozer",
        "attack_vector": "insecureshop://com.insecureshop/login?token=SECRET123",
        "legitimate_intercept": {
            "timestamp": "19:53:49",
            "component": "com.insecureshop/.WebViewActivity",
            "confirmed": True
        },
        "malicious_intercept": {
            "timestamp": "19:55:08",
            "component": "com.evil.hijacke/.WebViewActivity",
            "confirmed": True,
            "background_launch": True
        },
        "logcat_evidence": "logs/phase3_evidence.txt"
    },

    "phase4_forensic": {
        "malicious_score": 95,
        "max_score": 100,
        "clone_indicators": [
            "IDENTICAL app name",
            "IDENTICAL version number"
        ],
        "dangerous_permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE"
        ],
        "verdict": "DELIBERATE IMPERSONATION",
        "developer_oversight": False
    },

    "conclusion": (
        "The evidence conclusively demonstrates that com.evil.hijacke "
        "is a deliberate clone of com.insecureshop, designed to intercept "
        "deep-link intents containing authentication tokens. "
        "The identical app name, version number, and permission footprint, "
        "combined with the confirmed dynamic interception of token-bearing "
        "URIs, constitutes forensic proof of malicious intent. "
        "This is NOT a developer oversight."
    ),

    "recommendation": (
        "Immediate removal of com.evil.hijacke from the device. "
        "The legitimate app should migrate to Android App Links "
        "(https://) with Digital Asset Links verification to prevent "
        "future hijacking attempts."
    )
}

# Save JSON report
os.makedirs("reports", exist_ok=True)
report_path = f"reports/forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

# Print formatted report
print(Fore.CYAN + "\n" + "="*60)
print(Fore.CYAN + "   DROID-ATTRIBUTOR FORENSIC REPORT")
print(Fore.CYAN + "="*60)
print(f"\n  Case ID     : {report['case_id']}")
print(f"  Investigator: {report['investigator']}")
print(f"  Generated   : {report['generated']}")

print(Fore.CYAN + "\n--- EXECUTIVE SUMMARY ---")
print(f"\n  {report['executive_summary']}")

print(Fore.CYAN + "\n--- PHASE 2: COLLISION DETECTED ---")
print(Fore.RED + f"\n  Scheme    : {report['phase2_static']['scheme']}")
print(f"  Legit app : {report['phase2_static']['legitimate_app']['package']}")
print(f"  Evil app  : {report['phase2_static']['malicious_app']['package']}")

print(Fore.CYAN + "\n--- PHASE 3: DYNAMIC PROOF ---")
print(Fore.RED + f"\n  Token intercepted by evil app : ✅ CONFIRMED")
print(f"  Attack URI: {report['phase3_dynamic']['attack_vector']}")
print(f"  Background launch: {report['phase3_dynamic']['malicious_intercept']['background_launch']}")

print(Fore.CYAN + "\n--- PHASE 4: FORENSIC ATTRIBUTION ---")
print(Fore.RED + f"\n  Score  : {report['phase4_forensic']['malicious_score']}/100")
print(Fore.RED + f"  Verdict: {report['phase4_forensic']['verdict']} 🚨")
print(f"\n  Clone indicators:")
for c in report['phase4_forensic']['clone_indicators']:
    print(Fore.RED + f"    → {c}")

print(Fore.CYAN + "\n--- CONCLUSION ---")
print(f"\n  {report['conclusion']}")

print(Fore.CYAN + "\n--- RECOMMENDATION ---")
print(f"\n  {report['recommendation']}")

print(Fore.CYAN + "\n" + "="*60)
print(Fore.GREEN + f"\n[+] Report saved: {report_path}")
print(Fore.CYAN + "="*60)
