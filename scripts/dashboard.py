"""
dashboard.py — Droid-Attributor Forensic Dashboard
====================================================
Clean, professional web dashboard. White background, human-made look.

Usage:
  python scripts/dashboard.py
  python scripts/dashboard.py --report reports/full_pipeline_report_XYZ.json
  python scripts/dashboard.py --port 8080
"""

import os, sys, json, glob, argparse
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)
REPORT_DATA = {}

def load_latest_report(path=None):
    if path and os.path.exists(path):
        with open(path) as f: return json.load(f)
    files = sorted(glob.glob("reports/full_pipeline_report_*.json"), reverse=True)
    if not files:
        print("No reports found. Run run_pipeline.py first.")
        sys.exit(1)
    print(f"[+] Loading: {files[0]}")
    with open(files[0]) as f: return json.load(f)

def normalize_stats(s):
    s["malicious"]  = s.get("malicious",  s.get("malicious_confirmed", 0))
    s["suspicious"] = s.get("suspicious", 0)
    s["low_risk"]   = s.get("low_risk",   0)
    s["deliberate_hijacks"] = s.get("deliberate_hijacks", 0)
    s["parse_errors"]       = s.get("parse_errors", 0)
    return s

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Droid-Attributor | Forensic Report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: #f5f6f8;
    color: #1a1a2e;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 14px;
  }

  /* ── Header ── */
  header {
    background: #1a1a2e;
    color: #fff;
    padding: 14px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  header .brand { font-size: 17px; font-weight: 700; letter-spacing: 0.04em; }
  header .brand span { color: #e05c5c; }
  header .info { font-size: 12px; color: #aaa; text-align: right; line-height: 1.7; }

  /* ── Nav tabs ── */
  nav {
    background: #fff;
    border-bottom: 1px solid #dde1e7;
    padding: 0 32px;
    display: flex;
    gap: 4px;
  }
  nav a {
    display: inline-block;
    padding: 11px 18px;
    font-size: 13px;
    font-weight: 600;
    color: #555;
    text-decoration: none;
    border-bottom: 3px solid transparent;
    cursor: pointer;
  }
  nav a.active, nav a:hover { color: #1a1a2e; border-color: #e05c5c; }

  /* ── Layout ── */
  main { padding: 24px 32px; max-width: 1300px; margin: 0 auto; }

  /* ── Stat cards ── */
  .cards {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 14px;
    margin-bottom: 24px;
  }
  @media(max-width:900px){ .cards{ grid-template-columns: repeat(3,1fr); } }

  .card {
    background: #fff;
    border: 1px solid #dde1e7;
    border-radius: 6px;
    padding: 18px 16px 14px;
    text-align: center;
    border-top: 3px solid var(--c, #1a1a2e);
  }
  .card .num {
    font-size: 32px;
    font-weight: 700;
    color: var(--c, #1a1a2e);
    line-height: 1.1;
    margin-bottom: 6px;
  }
  .card .lbl {
    font-size: 11px;
    font-weight: 600;
    color: #888;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  /* ── Section heading ── */
  .sec-title {
    font-size: 13px;
    font-weight: 700;
    color: #1a1a2e;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 2px solid #eaedf0;
  }

  /* ── Panels ── */
  .panel {
    background: #fff;
    border: 1px solid #dde1e7;
    border-radius: 6px;
    padding: 20px;
  }

  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  @media(max-width:900px){ .two{ grid-template-columns:1fr; } }

  /* ── Charts ── */
  .chart-wrap { position: relative; height: 230px; }

  /* ── Table ── */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th {
    background: #f0f2f5;
    padding: 10px 12px;
    text-align: left;
    font-size: 11px;
    font-weight: 700;
    color: #555;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-bottom: 2px solid #dde1e7;
  }
  tbody td {
    padding: 10px 12px;
    border-bottom: 1px solid #f0f2f5;
    color: #333;
    vertical-align: middle;
  }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover td { background: #fafbfc; }

  .pkg { font-weight: 600; color: #1a1a2e; font-size: 12px; }
  .apk-name { font-size: 11px; color: #888; }

  /* ── Score bar ── */
  .bar-wrap { display: flex; align-items: center; gap: 8px; }
  .bar-track {
    flex: 1; height: 7px; background: #eaedf0;
    border-radius: 4px; overflow: hidden;
  }
  .bar-fill { height: 100%; border-radius: 4px; }
  .bar-score { font-size: 12px; font-weight: 700; width: 30px; text-align: right; }

  /* ── Badges ── */
  .badge {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
  }
  .b-red    { background: #fef0f0; color: #c0392b; border: 1px solid #f5c6c6; }
  .b-yellow { background: #fffbf0; color: #b7770d; border: 1px solid #f5e2a0; }
  .b-green  { background: #f0faf3; color: #27ae60; border: 1px solid #a8ddb9; }

  /* ── Collision / Hijack boxes ── */
  .coll-box {
    border: 1px solid #dde1e7;
    border-left: 4px solid #e05c5c;
    border-radius: 4px;
    padding: 12px 14px;
    margin-bottom: 10px;
    background: #fff9f9;
  }
  .coll-scheme { font-weight: 700; color: #c0392b; font-size: 14px; margin-bottom: 5px; }
  .coll-app { color: #555; font-size: 12px; line-height: 2; padding-left: 10px; }
  .coll-app b { color: #1a1a2e; }

  .hijack-box {
    border: 1px solid #f5c6c6;
    border-radius: 4px;
    padding: 12px 14px;
    margin-bottom: 10px;
    background: #fff9f9;
  }
  .hijack-label {
    font-size: 11px; font-weight: 700; color: #c0392b;
    text-transform: uppercase; letter-spacing: 0.07em;
    margin-bottom: 6px;
  }
  .hijack-apps { font-weight: 600; color: #1a1a2e; font-size: 13px; margin-bottom: 4px; }
  .hijack-detail { font-size: 11px; color: #777; line-height: 1.8; }
  .hijack-detail b { color: #b7770d; }

  /* ── Empty state ── */
  .empty { color: #27ae60; font-size: 13px; font-weight: 600; padding: 8px 0; }

  /* ── Footer ── */
  footer {
    margin-top: 32px;
    padding: 16px 32px;
    border-top: 1px solid #dde1e7;
    background: #fff;
    font-size: 11px;
    color: #aaa;
    text-align: center;
    letter-spacing: 0.05em;
  }
</style>
</head>
<body>

<header>
  <div class="brand">DROID<span>-</span>ATTRIBUTOR <span style="font-size:12px;color:#888;font-weight:400">v2.1</span></div>
  <div class="info">
    Investigator: {{ data.investigator }}<br>
    {{ data.institution }}<br>
    Generated: {{ data.generated }}
  </div>
</header>

<nav>
  <a class="active" href="#">Overview</a>
  <a href="#">APK Results</a>
  <a href="#">Collisions</a>
  <a href="#">Hijacks</a>
</nav>

<main>

  <!-- Stat cards -->
  <div class="cards">
    <div class="card" style="--c:#3498db">
      <div class="num">{{ data.stats.apks_scanned }}</div>
      <div class="lbl">APKs Scanned</div>
    </div>
    <div class="card" style="--c:#e67e22">
      <div class="num">{{ data.stats.collisions_found }}</div>
      <div class="lbl">Collisions</div>
    </div>
    <div class="card" style="--c:#e05c5c">
      <div class="num">{{ data.stats.deliberate_hijacks }}</div>
      <div class="lbl">Hijacks</div>
    </div>
    <div class="card" style="--c:#c0392b">
      <div class="num">{{ data.stats.malicious }}</div>
      <div class="lbl">Malicious</div>
    </div>
    <div class="card" style="--c:#e67e22">
      <div class="num">{{ data.stats.suspicious }}</div>
      <div class="lbl">Suspicious</div>
    </div>
    <div class="card" style="--c:#27ae60">
      <div class="num">{{ data.stats.low_risk }}</div>
      <div class="lbl">Low Risk</div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="two">
    <div class="panel">
      <div class="sec-title">Verdict Distribution</div>
      <div class="chart-wrap"><canvas id="donut"></canvas></div>
    </div>
    <div class="panel">
      <div class="sec-title">Attribution Scores per APK</div>
      <div class="chart-wrap"><canvas id="bar"></canvas></div>
    </div>
  </div>

  <!-- APK Table -->
  <div class="panel" style="margin-bottom:16px">
    <div class="sec-title">Per-APK Forensic Attribution</div>
    <table>
      <thead>
        <tr>
          <th style="width:30%">Package</th>
          <th style="width:22%">APK File</th>
          <th style="width:22%">Score</th>
          <th style="width:12%">Verdict</th>
          <th>Key Indicator</th>
        </tr>
      </thead>
      <tbody>
        {% for pkg, v in data.verdicts.items() | sort(attribute='1.score', reverse=True) %}
        <tr>
          <td><div class="pkg">{{ pkg }}</div></td>
          <td><div class="apk-name">{{ v.apk_file }}</div></td>
          <td>
            <div class="bar-wrap">
              <div class="bar-track">
                <div class="bar-fill" style="width:{{ v.score }}%;background:{% if v.score>=60 %}#c0392b{% elif v.score>=30 %}#e67e22{% else %}#27ae60{% endif %}"></div>
              </div>
              <div class="bar-score" style="color:{% if v.score>=60 %}#c0392b{% elif v.score>=30 %}#e67e22{% else %}#27ae60{% endif %}">{{ v.score }}</div>
            </div>
          </td>
          <td>
            {% if v.verdict=='MALICIOUS' %}<span class="badge b-red">MALICIOUS</span>
            {% elif v.verdict=='SUSPICIOUS' %}<span class="badge b-yellow">SUSPICIOUS</span>
            {% else %}<span class="badge b-green">LOW RISK</span>{% endif %}
          </td>
          <td style="color:#777;font-size:12px">
            {% if v.indicators %}{{ v.indicators[0][:55] }}{% if v.indicators[0]|length > 55 %}…{% endif %}{% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Collisions + Hijacks -->
  <div class="two">
    <div class="panel">
      <div class="sec-title">URI Scheme Collisions — {{ data.collisions | length }} found</div>
      {% if data.collisions %}
        {% for scheme, apps in data.collisions.items() %}
        <div class="coll-box">
          <div class="coll-scheme">{{ scheme }}://</div>
          <div class="coll-app">
            {% for a in apps %}→ <b>{{ a.package }}</b><br>{% endfor %}
          </div>
        </div>
        {% endfor %}
      {% else %}
        <div class="empty">✓ No collisions detected in this scan</div>
      {% endif %}
    </div>

    <div class="panel">
      <div class="sec-title">Confirmed Hijacks — Certificate Mismatch</div>
      {% set ns = namespace(found=false) %}
      {% for k, v in data.signature_comparison.items() %}
        {% if v.verdict == 'DIFFERENT_DEVELOPER' %}
          {% set ns.found = true %}
          <div class="hijack-box">
            <div class="hijack-label">⚠ Deliberate Hijack Confirmed</div>
            <div class="hijack-apps">{{ k.replace('|', ' vs ') }}</div>
            <div class="hijack-detail">
              Scheme: <b>{{ v.scheme }}://</b> &nbsp;|&nbsp; Confidence: <b>{{ v.confidence }}%</b><br>
              {% if v.sha256_a %}<b>Cert A:</b> {{ v.sha256_a[:36] }}…<br>{% endif %}
              {% if v.sha256_b %}<b>Cert B:</b> {{ v.sha256_b[:36] }}…{% endif %}
            </div>
          </div>
        {% endif %}
      {% endfor %}
      {% if not ns.found %}
        <div class="empty">✓ No certificate mismatches in current scan</div>
      {% endif %}
    </div>
  </div>

</main>

<footer>
  Droid-Attributor v2.1 &nbsp;·&nbsp;
  Automated Detection & Forensic Attribution of Android Deep-Link Hijacking &nbsp;·&nbsp;
  Gaurav Chandran K — 012200300004044 &nbsp;·&nbsp; NFSU Gandhinagar
</footer>

<script>
const stats    = {{ data.stats | tojson }};
const verdicts = {{ data.verdicts | tojson }};

// Donut
new Chart(document.getElementById('donut'), {
  type: 'doughnut',
  data: {
    labels: ['Malicious', 'Suspicious', 'Low Risk'],
    datasets: [{
      data: [
        stats.malicious || stats.malicious_confirmed || 0,
        stats.suspicious || 0,
        stats.low_risk || 0
      ],
      backgroundColor: ['#c0392b', '#e67e22', '#27ae60'],
      borderColor: '#fff',
      borderWidth: 3,
      hoverOffset: 4
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    cutout: '60%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#555', font: { size: 12 }, padding: 16, usePointStyle: true }
      }
    }
  }
});

// Bar
const pkgs   = Object.keys(verdicts);
const scores = pkgs.map(p => verdicts[p].score);
const colors = scores.map(s => s>=60 ? '#c0392b' : s>=30 ? '#e67e22' : '#27ae60');

new Chart(document.getElementById('bar'), {
  type: 'bar',
  data: {
    labels: pkgs.map(p => p.split('.').slice(-1)[0]),
    datasets: [{
      data: scores,
      backgroundColor: colors,
      borderRadius: 3,
      borderSkipped: false,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    scales: {
      y: {
        min: 0, max: 100,
        grid: { color: '#f0f2f5' },
        ticks: { color: '#888', font: { size: 11 } }
      },
      x: {
        grid: { display: false },
        ticks: { color: '#888', font: { size: 10 }, maxRotation: 45 }
      }
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          title: i => pkgs[i[0].dataIndex],
          label: i => ` Score: ${i.raw}/100`
        }
      }
    }
  }
});
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML, data=REPORT_DATA)

@app.route("/api/report")
def api_report():
    return jsonify(REPORT_DATA)

def main():
    parser = argparse.ArgumentParser(description="Droid-Attributor Dashboard")
    parser.add_argument("--report", default=None)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    global REPORT_DATA
    REPORT_DATA = load_latest_report(args.report)
    REPORT_DATA["stats"] = normalize_stats(REPORT_DATA["stats"])

    print(f"""
  Droid-Attributor Dashboard
  Report  : {REPORT_DATA.get('generated')}
  APKs    : {REPORT_DATA['stats']['apks_scanned']}
  Open    : http://{args.host}:{args.port}
""")
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
