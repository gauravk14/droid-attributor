from flask import Flask, render_template_string, jsonify
import json, os, glob

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Droid-Attributor Dashboard</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { background:#0d1117; color:#c9d1d9; font-family:monospace; }
    header { background:#161b22; border-bottom:1px solid #30363d;
             padding:16px 32px; display:flex; align-items:center; gap:16px; }
    header h1 { color:#58a6ff; font-size:20px; }
    header span { color:#8b949e; font-size:13px; }
    .grid { display:grid; grid-template-columns:repeat(3,1fr);
            gap:16px; padding:24px 32px; }
    .card { background:#161b22; border:1px solid #30363d;
            border-radius:8px; padding:20px; }
    .card h3 { color:#8b949e; font-size:12px; text-transform:uppercase;
               letter-spacing:1px; margin-bottom:8px; }
    .card .value { font-size:36px; font-weight:bold; }
    .red { color:#f85149; }
    .yellow { color:#e3b341; }
    .green { color:#3fb950; }
    .blue { color:#58a6ff; }
    .section { padding:0 32px 24px; }
    .section h2 { color:#58a6ff; font-size:16px; margin-bottom:16px;
                  padding-bottom:8px; border-bottom:1px solid #30363d; }
    table { width:100%; border-collapse:collapse; }
    th { background:#21262d; color:#8b949e; font-size:12px;
         text-align:left; padding:10px 14px; }
    td { padding:10px 14px; border-bottom:1px solid #21262d;
         font-size:13px; }
    tr:hover td { background:#1c2128; }
    .badge { padding:3px 10px; border-radius:12px; font-size:11px;
             font-weight:bold; }
    .badge.red { background:#3d1a1a; color:#f85149; }
    .badge.yellow { background:#2d2a1a; color:#e3b341; }
    .badge.green { background:#1a2d1a; color:#3fb950; }
    .chart-grid { display:grid; grid-template-columns:1fr 1fr;
                  gap:16px; padding:0 32px 24px; }
    .chart-card { background:#161b22; border:1px solid #30363d;
                  border-radius:8px; padding:20px; }
    .chart-card h3 { color:#8b949e; font-size:13px; margin-bottom:16px; }
    .collision-box { background:#3d1a1a; border:1px solid #f85149;
                     border-radius:8px; padding:16px; margin-bottom:12px; }
    .collision-box h4 { color:#f85149; margin-bottom:8px; }
    .collision-box p { color:#c9d1d9; font-size:13px; margin:4px 0; }
    footer { text-align:center; padding:24px; color:#8b949e; font-size:12px;
             border-top:1px solid #30363d; }
  </style>
</head>
<body>

<header>
  <div>
    <h1>⚡ Droid-Attributor</h1>
    <span>Android Deep-Link Hijacking Forensics Dashboard</span>
  </div>
  <div style="margin-left:auto;color:#8b949e;font-size:12px">
    Investigator: Gaurav Chandran K &nbsp;|&nbsp;
    <span id="ts"></span>
  </div>
</header>

<div class="grid">
  <div class="card">
    <h3>APKs Scanned</h3>
    <div class="value blue">{{ stats.apks_scanned }}</div>
  </div>
  <div class="card">
    <h3>Collisions Found</h3>
    <div class="value {{ 'red' if stats.collisions_found > 0 else 'green' }}">
      {{ stats.collisions_found }}
    </div>
  </div>
  <div class="card">
    <h3>Malicious Apps</h3>
    <div class="value {{ 'red' if stats.malicious_confirmed > 0 else 'green' }}">
      {{ stats.malicious_confirmed }}
    </div>
  </div>
</div>

{% if collisions %}
<div class="section">
  <h2>🚨 Collision Report</h2>
  {% for scheme, claimants in collisions.items() %}
  <div class="collision-box">
    <h4>scheme://{{ scheme }}</h4>
    {% for c in claimants %}
    <p>→ {{ c.package }} &nbsp;<span style="color:#8b949e">({{ c.apk_file }})</span></p>
    {% endfor %}
  </div>
  {% endfor %}
</div>
{% endif %}

<div class="section">
  <h2>📊 Forensic Verdicts</h2>
  <table>
    <tr>
      <th>Package</th>
      <th>Score</th>
      <th>Verdict</th>
      <th>Indicators</th>
    </tr>
    {% for pkg, v in verdicts.items() %}
    <tr>
      <td>{{ pkg }}</td>
      <td>{{ v.score }}/100</td>
      <td>
        {% if v.verdict == 'MALICIOUS' %}
        <span class="badge red">MALICIOUS 🚨</span>
        {% elif v.verdict == 'SUSPICIOUS' %}
        <span class="badge yellow">SUSPICIOUS ⚠️</span>
        {% else %}
        <span class="badge green">LOW RISK ✅</span>
        {% endif %}
      </td>
      <td style="color:#8b949e">{{ v.indicators | join(', ') }}</td>
    </tr>
    {% endfor %}
  </table>
</div>

<div class="chart-grid">
  <div class="chart-card">
    <h3>Verdict Distribution</h3>
    <canvas id="verdictChart" height="200"></canvas>
  </div>
  <div class="chart-card">
    <h3>Risk Scores</h3>
    <canvas id="scoreChart" height="200"></canvas>
  </div>
</div>

<footer>
  Droid-Attributor &nbsp;|&nbsp;
  Automated Detection and Forensic Attribution of Android Deep-Link Hijacking
  &nbsp;|&nbsp; Gaurav Chandran K — 012200300004044
</footer>

<script>
document.getElementById('ts').textContent = new Date().toLocaleString();

const verdicts = {{ verdicts_json | safe }};
const pkgs = Object.keys(verdicts);
const scores = pkgs.map(p => verdicts[p].score);
const colors = pkgs.map(p =>
  verdicts[p].verdict === 'MALICIOUS' ? '#f85149' :
  verdicts[p].verdict === 'SUSPICIOUS' ? '#e3b341' : '#3fb950'
);

// Verdict distribution pie
const counts = {MALICIOUS:0, SUSPICIOUS:0, 'LOW RISK':0};
Object.values(verdicts).forEach(v => counts[v.verdict]++);

new Chart(document.getElementById('verdictChart'), {
  type: 'doughnut',
  data: {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: ['#f85149','#e3b341','#3fb950'],
      borderWidth: 0
    }]
  },
  options: {
    plugins: { legend: { labels: { color:'#c9d1d9' } } }
  }
});

// Score bar chart
new Chart(document.getElementById('scoreChart'), {
  type: 'bar',
  data: {
    labels: pkgs.map(p => p.split('.').pop()),
    datasets: [{
      label: 'Risk Score',
      data: scores,
      backgroundColor: colors,
      borderRadius: 4
    }]
  },
  options: {
    scales: {
      y: { max:100, ticks:{color:'#8b949e'}, grid:{color:'#21262d'} },
      x: { ticks:{color:'#8b949e'}, grid:{color:'#21262d'} }
    },
    plugins: { legend: { display:false } }
  }
});
</script>
</body>
</html>
"""

def load_latest_report():
    files = glob.glob("reports/full_pipeline_report_*.json")
    if not files:
        return None
    latest = max(files, key=os.path.getmtime)
    with open(latest) as f:
        return json.load(f)

@app.route("/")
def index():
    report = load_latest_report()
    if not report:
        return "No report found. Run python3 scripts/run_pipeline.py first."
    return render_template_string(HTML,
        stats=report["stats"],
        collisions=report["collisions"],
        verdicts=report["verdicts"],
        verdicts_json=json.dumps(report["verdicts"])
    )

@app.route("/api/report")
def api_report():
    report = load_latest_report()
    return jsonify(report)

if __name__ == "__main__":
    print("[*] Droid-Attributor Dashboard")
    print("[*] Open: http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
