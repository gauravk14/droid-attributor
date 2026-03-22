from androguard.misc import AnalyzeAPK
from colorama import Fore, init
import json, os

init(autoreset=True)

# Known exfiltration patterns in decompiled code
EXFIL_PATTERNS = {
    "HTTP POST to external": [
        "openConnection", "HttpURLConnection",
        "OkHttpClient", "Volley", "RequestQueue"
    ],
    "Data being sent": [
        "getOutputStream", "write", "flush",
        "execute", "enqueue"
    ],
    "Sensitive data access": [
        "getIntent", "getData", "getDataString",
        "getQueryParameter", "getToken",
        "getPassword", "getEmail"
    ],
    "Device fingerprinting": [
        "getDeviceId", "getSubscriberId",
        "getSimSerialNumber", "getImei",
        "getMacAddress", "getAndroidId"
    ],
    "Crypto/obfuscation": [
        "SecretKeySpec", "IvParameterSpec",
        "Cipher", "Base64", "AESUtil"
    ]
}

NETWORK_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE"
]

def detect_exfiltration(apk_path):
    print(Fore.CYAN + f"\n[*] Exfiltration Analysis: {apk_path}")
    print(Fore.CYAN + "=" * 55)

    apk, d, dx = AnalyzeAPK(apk_path)
    package = apk.get_package()
    findings = {}
    total_hits = 0

    # Check network permissions first
    perms = apk.get_permissions()
    has_network = any(p in perms for p in NETWORK_PERMISSIONS)

    if has_network:
        print(Fore.YELLOW + "\n[!] App has INTERNET permission — can exfiltrate data")
    else:
        print(Fore.GREEN + "\n[+] No network permission — cannot exfiltrate")
        return {}

    # Deep scan all classes and methods
    for category, patterns in EXFIL_PATTERNS.items():
        hits = []
        for cls in dx.get_classes():
            cls_name = str(cls.name)
            # Skip standard Android/Java classes
            if any(skip in cls_name for skip in [
                "Landroid/", "Ljava/", "Lkotlin/",
                "Lcom/google/", "Lcom/squareup/",
                "Lretrofit2/", "Lokhttp3/"
            ]):
                continue

            for method in cls.get_methods():
                method_name = str(method.name)
                for _, call, _ in method.get_xref_to():
                    call_str = str(call.name)
                    class_str = str(call.class_name)
                    for pattern in patterns:
                        if pattern in call_str or pattern in class_str:
                            entry = f"{cls_name}->{method_name}() → {pattern}"
                            if entry not in hits:
                                hits.append(entry)

        if hits:
            findings[category] = hits[:3]  # Top 3 per category
            total_hits += len(hits)
            print(Fore.YELLOW + f"\n[!] {category} ({len(hits)} hits):")
            for h in hits[:3]:
                print(f"    → {h}")

    # Exfiltration chain detection
    # Most dangerous: app handles intent AND has network calls
    has_intent_handler = "Sensitive data access" in findings
    has_network_call = "HTTP POST to external" in findings or \
                       "Data being sent" in findings

    print(Fore.CYAN + "\n--- EXFILTRATION CHAIN ANALYSIS ---")

    if has_intent_handler and has_network_call:
        print(Fore.RED + "\n[!!] COMPLETE EXFILTRATION CHAIN DETECTED:")
        print(Fore.RED + "     Intent data → Network transmission")
        print(Fore.RED + "     This app CAN steal deep-link tokens!")
        chain_confirmed = True
    elif has_intent_handler:
        print(Fore.YELLOW + "\n[~] Partial chain: reads intent data")
        print(Fore.YELLOW + "    but no confirmed network transmission")
        chain_confirmed = False
    elif has_network_call:
        print(Fore.YELLOW + "\n[~] Has network calls but no intent reading")
        chain_confirmed = False
    else:
        print(Fore.GREEN + "\n[+] No exfiltration chain found")
        chain_confirmed = False

    result = {
        "package": package,
        "apk_path": apk_path,
        "has_network_permission": has_network,
        "findings": findings,
        "total_hits": total_hits,
        "exfiltration_chain_confirmed": chain_confirmed
    }

    return result

# Run on both APKs
results = {}

print(Fore.CYAN + "\n" + "="*55)
print(Fore.CYAN + "  DROID-ATTRIBUTOR — EXFILTRATION DETECTOR")
print(Fore.CYAN + "="*55)

for apk_name in ["InsecureShop.apk", "evil_hijacker.apk"]:
    path = f"apks/{apk_name}"
    if os.path.exists(path):
        result = detect_exfiltration(path)
        results[apk_name] = result

# Save results
os.makedirs("reports", exist_ok=True)
with open("reports/exfiltration_report.json", "w") as f:
    json.dump(results, f, indent=2)

print(Fore.CYAN + "\n" + "="*55)
print(Fore.CYAN + "  FINAL EXFILTRATION SUMMARY")
print(Fore.CYAN + "="*55)

for apk_name, result in results.items():
    if result:
        chain = result.get("exfiltration_chain_confirmed", False)
        hits = result.get("total_hits", 0)
        pkg = result.get("package", "unknown")
        status = Fore.RED + "CHAIN CONFIRMED 🚨" if chain \
            else Fore.YELLOW + "PARTIAL ⚠️"
        print(f"\n  {pkg}")
        print(f"  Hits  : {hits}")
        print(f"  Status: {status}")

print(Fore.GREEN + "\n[+] Saved: reports/exfiltration_report.json")
