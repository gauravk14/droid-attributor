# Droid-Attributor 🔍

**Automated Detection and Forensic Attribution of Android Deep-Link Hijacking**

[![Python](https://img.shields.io/badge/Python-3.13-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Android-green)](https://android.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 📌 Overview

Droid-Attributor is a forensic framework that detects Android deep-link
hijacking attacks and produces evidence-grade attribution reports distinguishing
**deliberate malicious intent** from **developer oversight**.

> Built as B.Tech-M.Tech final year project at  
> **National Forensic Sciences University, Gandhinagar**  
> Guide: Mr. Prakash Khasor

---

## 🚨 The Problem

Android apps using custom URI schemes (e.g. `myapp://`) are vulnerable to
**Intent-Filter Collisions** — where a malicious app registers the same scheme
to silently intercept authentication tokens.

**Existing tools detect the vulnerability. None prove malicious intent.**
Droid-Attributor fills this forensic gap.

---

## ⚡ Features

- ✅ Automated APK scanning using Androguard
- ✅ Intent-filter collision detection across multiple APKs
- ✅ Dynamic attack simulation via Drozer + ADB
- ✅ Forensic attribution scoring (0-100)
- ✅ Clone detection (identical app name, version, certificate)
- ✅ Exfiltration chain analysis
- ✅ Web dashboard (Flask + Chart.js)
- ✅ JSON forensic report generation
- ✅ Full pipeline in one command

---

## 🏗️ Architecture
```
Phase 1: APK Collection     → Dataset of APKs
Phase 2: Static Analysis    → Androguard collision detection
Phase 3: Dynamic Validation → Drozer attack simulation
Phase 4: Forensic Attribution → Scoring engine (0-100)
Phase 5: Report Generation  → JSON report + Web dashboard
```

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.13 | Core language |
| Androguard | APK parsing & static analysis |
| Drozer | Dynamic attack simulation |
| ADB | Android device bridge |
| Genymotion | Android 11 emulator |
| Flask | Web dashboard |
| Chart.js | Data visualisation |
| Kali Linux | Security research OS |

---

## 🚀 Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/droid-attributor.git
cd droid-attributor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 📖 Usage

### Run Full Pipeline
```bash
python3 scripts/run_pipeline.py
```

### Run Individual Phases
```bash
# Phase 2: Static Analysis
python3 scripts/collision_detector.py

# Phase 4: Forensic Attribution
python3 scripts/forensic_attribution.py

# Phase 4: Exfiltration Detection
python3 scripts/exfiltration_detector.py

# Phase 5: Generate Report
python3 scripts/generate_report.py

# Launch Web Dashboard
python3 scripts/dashboard.py
# Open: http://localhost:5000
```

### Dynamic Attack (Drozer)
```bash
# Connect Genymotion
adb connect 192.168.56.101:5555
adb forward tcp:31415 tcp:31415
drozer console connect

# Inside Drozer
run app.activity.start --component com.insecureshop \
  com.insecureshop.WebViewActivity \
  --data-uri "insecureshop://com.insecureshop/login?token=SECRET123"
```

---

## 📊 Results

| APK | Scheme | Score | Verdict |
|-----|--------|-------|---------|
| InsecureShop.apk | insecureshop:// | 50/100 | MALICIOUS |
| evil_hijacker.apk | insecureshop:// | 95/100 | DELIBERATE IMPERSONATION |
| InsecureBankv2.apk | None | 30/100 | SUSPICIOUS |
| UnCrackable 1/2/3 | None | 0/100 | LOW RISK |

---

## 📁 Project Structure
```
droid-attributor/
├── apks/                          # APK dataset
├── scripts/
│   ├── run_pipeline.py            # Main pipeline
│   ├── collision_detector.py      # Phase 2
│   ├── forensic_attribution.py    # Phase 4
│   ├── exfiltration_detector.py   # Phase 4
│   ├── generate_report.py         # Phase 5
│   ├── dashboard.py               # Web dashboard
│   └── download_dataset.py        # Dataset downloader
├── reports/                       # Generated reports
├── logs/                          # Attack evidence
├── requirements.txt
└── README.md
```

---

## ⚠️ Disclaimer

This tool is developed strictly for **educational and forensic research purposes**
at National Forensic Sciences University. Only use on devices and applications
you have explicit permission to test.

---

## 👤 Author

**Gaurav Chandran K**  
B.Tech-M.Tech Computer Science (SEM 8)  

----
## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
