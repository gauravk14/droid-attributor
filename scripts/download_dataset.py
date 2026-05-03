"""
download_dataset.py — Droid-Attributor Dataset Downloader
==========================================================
Supports two sources:
  1. AndroZoo      — academic APK dataset (requires free API key)
  2. MalwareBazaar — real Android malware samples (requires free API key)

Usage:
  python scripts/download_dataset.py --source malwarebazaar --key YOUR_KEY --count 10
  python scripts/download_dataset.py --source androzoo --key YOUR_KEY --count 20
  python scripts/download_dataset.py --source both --key YOUR_KEY --count 15
"""

import os
import sys
import time
import shutil
import hashlib
import argparse
import subprocess
import tempfile
import requests
from pathlib import Path

# ── Output folders ────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.parent
APK_DIR    = BASE_DIR / "apks" / "dataset"
REPORT_DIR = BASE_DIR / "reports"

APK_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ── AndroZoo ──────────────────────────────────────────────────────────────────
ANDROZOO_API  = "https://androzoo.uni.lu/api/download"
ANDROZOO_LIST = "https://androzoo.uni.lu/api/get_list"


def download_androzoo(api_key: str, count: int) -> list[dict]:
    print("\n📦 [AndroZoo] Starting download...")
    results = []
    params = {
        "apikey":  api_key,
        "limit":   count,
        "markets": "appchina,anzhi,slideme",
    }
    try:
        resp = requests.get(ANDROZOO_LIST, params=params, timeout=30)
        resp.raise_for_status()
        lines = resp.text.strip().split("\n")[1:]
        for line in lines[:count]:
            parts = line.split(",")
            if len(parts) < 2:
                continue
            sha256 = parts[0].strip().strip('"')
            pkg    = parts[1].strip().strip('"') if len(parts) > 1 else "unknown"
            result = _androzoo_download_single(api_key, sha256, pkg)
            if result:
                results.append(result)
            time.sleep(1)
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401:
            print("   ❌ Invalid API key. Get one free at https://androzoo.uni.lu/access")
        else:
            print(f"   ❌ AndroZoo API error: {e}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    return results


def _androzoo_download_single(api_key: str, sha256: str, pkg: str) -> dict | None:
    out_path = APK_DIR / f"{pkg}_{sha256[:8]}.apk"
    if out_path.exists():
        print(f"   ✅ Already exists: {out_path.name}")
        return {"source": "androzoo", "sha256": sha256, "package": pkg, "path": str(out_path)}
    try:
        params = {"apikey": api_key, "sha256": sha256}
        resp   = requests.get(ANDROZOO_API, params=params, stream=True, timeout=60)
        resp.raise_for_status()
        with open(out_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        actual = _sha256(out_path)
        ok = actual.lower() == sha256.lower()
        print(f"   {'✅' if ok else '⚠️ hash mismatch'} {out_path.name} ({out_path.stat().st_size // 1024} KB)")
        return {"source": "androzoo", "sha256": sha256, "package": pkg,
                "path": str(out_path), "verified": ok}
    except Exception as e:
        print(f"   ❌ Failed {sha256[:12]}…: {e}")
        return None


# ── MalwareBazaar ─────────────────────────────────────────────────────────────
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


def download_malwarebazaar(count: int, api_key: str = None) -> list[dict]:
    print("\n🦠 [MalwareBazaar] Fetching Android malware samples...")
    print("   ℹ️  Source: https://bazaar.abuse.ch — real malware, research use only\n")

    if not api_key:
        print("   ❌ MalwareBazaar requires an API key.")
        print("   👉 Get free at: https://bazaar.abuse.ch/api/#anchor_auth")
        return []

    headers = {
        "Auth-Key":     api_key,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    results = []
    tags_to_try = ["Android", "BankBot", "FluBot", "Cerberus", "Anubis"]

    for tag in tags_to_try:
        if len(results) >= count:
            break
        try:
            resp = requests.post(
                MALWAREBAZAAR_API,
                headers=headers,
                data={"query": "get_taginfo", "tag": tag, "limit": min(count, 10)},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("query_status") != "ok":
                print(f"   ⚠️  Tag '{tag}': {data.get('query_status')}")
                continue

            for sample in data.get("data", []):
                if len(results) >= count:
                    break
                if sample.get("file_type") != "apk":
                    continue
                result = _malwarebazaar_download_single(sample, headers)
                if result:
                    results.append(result)
                time.sleep(1)

        except Exception as e:
            print(f"   ❌ Tag '{tag}' failed: {e}")

    return results


def _malwarebazaar_download_single(sample: dict, headers: dict) -> dict | None:
    sha256   = sample.get("sha256_hash", "")
    pkg      = sample.get("file_name", sha256[:12]).replace(".apk", "")
    tag      = sample.get("tags", ["unknown"])[0] if sample.get("tags") else "unknown"
    out_path = APK_DIR / f"malware_{tag}_{sha256[:8]}.apk"

    if out_path.exists():
        print(f"   ✅ Already exists: {out_path.name}")
        return {"source": "malwarebazaar", "sha256": sha256, "package": pkg,
                "path": str(out_path), "family": tag}
    try:
        resp = requests.post(
            MALWAREBAZAAR_API,
            headers=headers,
            data={"query": "get_file", "sha256_hash": sha256},
            timeout=60,
        )
        resp.raise_for_status()

        # Save to temp, extract with 7z (handles Zstandard compression)
        tmp_zip = Path(tempfile.mktemp(suffix=".zip"))
        tmp_dir = Path(tempfile.mkdtemp())
        tmp_zip.write_bytes(resp.content)

        result = subprocess.run(
            ["7z", "x", str(tmp_zip), f"-o{tmp_dir}", "-pinfected", "-y"],
            capture_output=True, text=True
        )
        tmp_zip.unlink(missing_ok=True)

        if result.returncode != 0:
            print(f"   ⚠️  7z failed for {sha256[:12]}: {result.stderr[:100]}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None

        apk_files = list(tmp_dir.rglob("*.apk"))
        if not apk_files:
            print(f"   ⚠️  No APK in archive for {sha256[:12]}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None

        # shutil.move works across different filesystems (fixes cross-device link error)
        shutil.move(str(apk_files[0]), str(out_path))
        shutil.rmtree(tmp_dir, ignore_errors=True)

        size = out_path.stat().st_size // 1024
        print(f"   ✅ Downloaded: {out_path.name} | Family: {tag} | {size} KB")

        return {
            "source":  "malwarebazaar",
            "sha256":  sha256,
            "package": pkg,
            "path":    str(out_path),
            "family":  tag,
        }

    except Exception as e:
        print(f"   ❌ Failed {sha256[:12]}…: {e}")
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def save_manifest(results: list[dict]) -> None:
    manifest_path = APK_DIR / "manifest.csv"
    with open(manifest_path, "w") as f:
        f.write("source,sha256,package,family,path\n")
        for r in results:
            f.write(
                f"{r.get('source','')},{r.get('sha256','')},{r.get('package','')},"
                f"{r.get('family','N/A')},{r.get('path','')}\n"
            )
    print(f"\n📄 Manifest saved: {manifest_path}")


def print_summary(results: list[dict]) -> None:
    print("\n" + "=" * 55)
    print("📊 DOWNLOAD SUMMARY")
    print("=" * 55)
    az = [r for r in results if r["source"] == "androzoo"]
    mb = [r for r in results if r["source"] == "malwarebazaar"]
    print(f"  Total downloaded  : {len(results)} APKs")
    print(f"  From AndroZoo     : {len(az)}")
    print(f"  From MalwareBazaar: {len(mb)}")
    print(f"  Saved to          : {APK_DIR}")
    print("=" * 55)
    print("\n🚀 Next step: Run your pipeline!")
    print("   python scripts/run_pipeline.py --input apks/dataset/")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Droid-Attributor Dataset Downloader")
    parser.add_argument(
        "--source", choices=["androzoo", "malwarebazaar", "both"],
        default="malwarebazaar",
    )
    parser.add_argument("--key", default=None, help="API key")
    parser.add_argument("--count", type=int, default=10)
    args = parser.parse_args()

    if not args.key:
        print("❌ --key is required.")
        print("   MalwareBazaar: https://bazaar.abuse.ch/api/#anchor_auth")
        print("   AndroZoo:      https://androzoo.uni.lu/access")
        sys.exit(1)

    print("╔══════════════════════════════════════════════════════╗")
    print("║      Droid-Attributor — Dataset Downloader          ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"  Source : {args.source}")
    print(f"  Count  : {args.count} APKs per source")
    print(f"  Output : {APK_DIR}")

    all_results = []

    if args.source in ("malwarebazaar", "both"):
        all_results += download_malwarebazaar(args.count, api_key=args.key)

    if args.source in ("androzoo", "both"):
        all_results += download_androzoo(args.key, args.count)

    if all_results:
        save_manifest(all_results)

    print_summary(all_results)


if __name__ == "__main__":
    main()
