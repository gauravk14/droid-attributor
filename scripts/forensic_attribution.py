from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import ExternalMethod
import re
from colorama import Fore, Style, init

init(autoreset=True)

SUSPICIOUS_APIS = [
    "HttpURLConnection",
    "OkHttpClient",
    "Volley",
    "URLConnection",
    "Socket",
    "sendTextMessage",
    "execSQL",
    "getDeviceId",
    "getSubscriberId",
    "getPassword",
    "getIntent",
    "getData",
]

EXFIL_KEYWORDS = [
    "token", "password", "secret",
    "credential", "auth", "login",
    "cookie", "session", "key"
]

def analyze_apk(apk_path, package_name):
    print(Fore.CYAN + f"\n[*] Forensic Analysis: {apk_path}")
    print(Fore.CYAN + "=" * 50)

    apk, d, dx = AnalyzeAPK(apk_path)
    
    score = 0
    evidence = []

    # Check 1 — Dangerous permissions
    perms = apk.get_permissions()
    dangerous = [p for p in perms if any(x in p for x in
        ["INTERNET", "READ_CONTACTS", "READ_SMS",
         "RECORD_AUDIO", "ACCESS_FINE_LOCATION"])]
    
    if dangerous:
        score += len(dangerous) * 10
        evidence.append({
            "type": "Dangerous Permissions",
            "detail": dangerous,
            "weight": len(dangerous) * 10
        })
        print(Fore.YELLOW + f"\n[!] Dangerous permissions ({len(dangerous)}):")
        for p in dangerous:
            print(f"    {p}")

    # Check 2 — Network API usage
    network_calls = []
    for cls in dx.get_classes():
        for method in cls.get_methods():
            for _, call, _ in method.get_xref_to():
                call_name = str(call.name)
                class_name = str(call.class_name)
                for api in SUSPICIOUS_APIS:
                    if api in class_name or api in call_name:
                        network_calls.append(
                            f"{cls.name}->{method.name} calls {class_name}->{call_name}"
                        )

    if network_calls:
        score += 30
        evidence.append({
            "type": "Network API Calls",
            "detail": network_calls[:5],
            "weight": 30
        })
        print(Fore.YELLOW + f"\n[!] Suspicious network calls ({len(network_calls)}):")
        for c in network_calls[:5]:
            print(f"    {c}")

    # Check 3 — Intent data handling
    intent_handlers = []
    for cls in dx.get_classes():
        for method in cls.get_methods():
            src = str(method.name)
            if any(x in src for x in ["getIntent", "getData", "getDataString"]):
                intent_handlers.append(f"{cls.name}->{method.name}")

    if intent_handlers:
        score += 20
        evidence.append({
            "type": "Intent Data Handlers",
            "detail": intent_handlers,
            "weight": 20
        })
        print(Fore.YELLOW + f"\n[!] Intent handlers found ({len(intent_handlers)}):")
        for h in intent_handlers[:5]:
            print(f"    {h}")

    # Final verdict
    print(Fore.CYAN + "\n" + "=" * 50)
    print(Fore.CYAN + "[*] FORENSIC ATTRIBUTION SCORE")
    print(Fore.CYAN + "=" * 50)
    print(f"\n  Package : {package_name}")
    print(f"  Score   : {score}/100")

    if score >= 50:
        print(Fore.RED + f"  Verdict : LIKELY MALICIOUS 🚨")
    elif score >= 25:
        print(Fore.YELLOW + f"  Verdict : SUSPICIOUS ⚠️")
    else:
        print(Fore.GREEN + f"  Verdict : LOW RISK ✅")

    return score, evidence

# Analyze both APKs
legit_score, legit_ev = analyze_apk(
    "apks/InsecureShop.apk", "com.insecureshop")

evil_score, evil_ev = analyze_apk(
    "apks/evil_hijacker.apk", "com.evil.hijacke")

# Comparison with clone detection
print(Fore.CYAN + "\n" + "=" * 50)
print(Fore.CYAN + "[*] COMPARATIVE VERDICT")
print(Fore.CYAN + "=" * 50)
print(f"\n  Legitimate app score : {legit_score}/100")
print(f"\n  Malicious app score  : {evil_score}/100")

# Check if evil app is a clone
from androguard.misc import AnalyzeAPK as AAPK
apk1, _, _ = AAPK("apks/InsecureShop.apk")
apk2, _, _ = AAPK("apks/evil_hijacker.apk")

legit_pkg = apk1.get_package()
evil_pkg = apk2.get_package()

# Check shared certificate
legit_cert = apk1.get_certificates_der_v2()
evil_cert = apk2.get_certificates_der_v2()

clone_indicators = []

# Same certificate = definitely cloned
if legit_cert and evil_cert and legit_cert == evil_cert:
    clone_indicators.append("IDENTICAL certificate signature")
    evil_score += 25

# Same app name
if apk1.get_app_name() == apk2.get_app_name():
    clone_indicators.append("IDENTICAL app name")
    evil_score += 15

# Same version
if apk1.get_androidversion_name() == apk2.get_androidversion_name():
    clone_indicators.append("IDENTICAL version number")
    evil_score += 10

if clone_indicators:
    print(Fore.RED + "\n  [!!] CLONE INDICATORS DETECTED:")
    for c in clone_indicators:
        print(Fore.RED + f"      → {c}")
    print(Fore.RED + f"\n  Adjusted malicious score: {evil_score}/100")
    print(Fore.RED + "\n  Verdict: DELIBERATE IMPERSONATION 🚨")
    print(Fore.RED + "  This is NOT a developer oversight.")
else:
    if evil_score > legit_score:
        print(Fore.RED + "\n  Verdict: LIKELY MALICIOUS INTENT 🚨")
    else:
        print(Fore.YELLOW + "\n  Verdict: COLLISION MAY BE ACCIDENTAL ⚠️")

print(Fore.CYAN + "\n[*] Analysis complete. Run report generator next.")
