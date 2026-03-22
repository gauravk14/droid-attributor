import subprocess
import os

# Curated list of open-source vulnerable/research APKs
APKS = [
    # Deliberately vulnerable apps (legal to use)
    ("https://github.com/dineshshetty/Android-InsecureBankv2/raw/master/InsecureBankv2.apk", "InsecureBankv2.apk"),
    ("https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_01/UnCrackable-Level1.apk", "UnCrackable1.apk"),
    ("https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_02/UnCrackable-Level2.apk", "UnCrackable2.apk"),
    ("https://github.com/OWASP/owasp-mastg/raw/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk", "UnCrackable3.apk"),
    ("https://github.com/oversecured/ovaa/releases/download/v1.0/ovaa.apk", "ovaa.apk"),
    ("https://github.com/rewanthtammana/Damn-Vulnerable-Bank/releases/download/v1.0.0/dvba.apk", "DamnVulnerableBank.apk"),
]

os.makedirs("apks", exist_ok=True)
downloaded = 0
failed = []

print("[*] Downloading APK dataset...")
print("="*50)

for url, filename in APKS:
    dest = f"apks/{filename}"
    if os.path.exists(dest) and os.path.getsize(dest) > 10000:
        print(f"[+] Already exists: {filename}")
        downloaded += 1
        continue

    print(f"[*] Downloading: {filename}")
    try:
        result = subprocess.run(
            ["wget", "-q", "--timeout=30", "-O", dest, url],
            capture_output=True, timeout=60
        )
        size = os.path.getsize(dest)
        if size > 10000:
            print(f"[+] OK: {filename} ({size//1024}KB)")
            downloaded += 1
        else:
            print(f"[-] Failed (too small): {filename}")
            os.remove(dest)
            failed.append(filename)
    except Exception as e:
        print(f"[-] Error: {filename} — {e}")
        failed.append(filename)

print(f"\n[*] Downloaded: {downloaded}/{len(APKS)}")
print(f"[*] APKs in dataset: {len(os.listdir('apks'))}")

if failed:
    print(f"[-] Failed: {failed}")
    print("[*] You can manually add APKs to apks/ folder")
