import zipfile
import os

# Paths
manifest_path = "temp/evil_app/AndroidManifest.xml"
output_apk = "apks/evil_hijacker.apk"

print("[*] Creating fake malicious APK...")

with zipfile.ZipFile(output_apk, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.write(manifest_path, "AndroidManifest.xml")
    # Add a dummy classes.dex so it looks like a real APK
    zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
    zf.writestr("resources.arsc", b"\x00" * 8)

print(f"[+] Created: {output_apk}")
print(f"[+] Size: {os.path.getsize(output_apk)} bytes")
