#!/usr/bin/env python3
"""
NetWatch - Générateur de dashboard 
Lancer ce script après netwatch.py pour obtenir le rapport visuel.
"""

import json
import sys
from pathlib import Path
from datetime import datetime


def generate_html_report(report_data: dict, output_path: str = "netwatch_dashboard.html"):
    """dDashboard à partir des données d'analyse"""

    stats = report_data.get("stats", {})
    alerts = report_data.get("alerts", [])
    meta = report_data.get("metadata", {})

    #Préparation données JSON pour injection dans  HTML
    protocol_data = stats.get("protocol_counts", {})
    top_talkers = stats.get("top_talkers", [])
    top_ports = stats.get("top_targeted_ports", [])
    alerts_by_sev = stats.get("alerts_by_severity", {})
    alerts_by_cat = stats.get("alerts_by_category", {})
    risk_score = stats.get("risk_score", 0)
    risk_level = stats.get("risk_level", "FAIBLE")

    risk_color = {
        "CRITIQUE": "#ff2d55",
        "ÉLEVÉ": "#ff6b2d",
        "MOYEN": "#f0c040",
        "FAIBLE": "#30d158"
    }.get(risk_level, "#30d158")

    alerts_json = json.dumps(alerts, ensure_ascii=False)
    protocol_json = json.dumps(protocol_data)
    talkers_json = json.dumps(top_talkers)
    ports_json = json.dumps(top_ports)
    sev_json = json.dumps(alerts_by_sev)
    cat_json = json.dumps(alerts_by_cat)

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatch — Dashboard Sécurité Réseau</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');

  :root {{
    --bg: #0a0e1a;
    --surface: #0f1729;
    --surface2: #141e35;
    --border: #1e2d50;
    --accent: #00d4ff;
    --accent2: #7c3aed;
    --text: #e2e8f0;
    --text-dim: #64748b;
    --red: #ff2d55;
    --orange: #ff6b2d;
    --yellow: #f0c040;
    --green: #30d158;
    --font-mono: 'JetBrains Mono', monospace;
    --font-display: 'Syne', sans-serif;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-display);
    min-height: 100vh;
    overflow-x: hidden;
  }}

  body::before {{
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }}

  .container {{ max-width: 1400px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }}

  
  header {{
    border-bottom: 1px solid var(--border);
    padding: 20px 0;
    margin-bottom: 32px;
  }}
  .header-inner {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .logo {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .logo-icon {{
    width: 44px; height: 44px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
  }}
  .logo h1 {{ font-size: 1.6rem; font-weight: 800; letter-spacing: -0.5px; }}
  .logo span {{ color: var(--accent); }}
  .header-meta {{ font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-dim); text-align: right; }}
  .header-meta strong {{ color: var(--text); }}

  .risk-badge {{
    display: flex; align-items: center; gap: 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px 20px;
    margin-bottom: 28px;
  }}
  .risk-circle {{
    width: 70px; height: 70px;
    border-radius: 50%;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    border: 3px solid;
    flex-shrink: 0;
  }}
  .risk-circle .score {{ font-size: 1.4rem; font-weight: 800; }}
  .risk-circle .label {{ font-size: 0.55rem; color: var(--text-dim); }}
  .risk-info h2 {{ font-size: 1.1rem; font-weight: 700; }}
  .risk-info p {{ font-size: 0.8rem; color: var(--text-dim); margin-top: 4px; font-family: var(--font-mono); }}

  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s, border-color 0.2s;
  }}
  .stat-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
  .stat-card::after {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    opacity: 0;
    transition: opacity 0.2s;
  }}
  .stat-card:hover::after {{ opacity: 1; }}
  .stat-icon {{ font-size: 1.4rem; margin-bottom: 8px; }}
  .stat-value {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
  .stat-label {{ font-size: 0.72rem; color: var(--text-dim); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}

  .sev-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 28px;
  }}
  .sev-card {{
    border-radius: 10px;
    padding: 14px 16px;
    border: 1px solid;
    display: flex; align-items: center; gap: 10px;
  }}
  .sev-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  .sev-info .count {{ font-size: 1.8rem; font-weight: 800; line-height: 1; }}
  .sev-info .name {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; }}
  .sev-critical {{ background: rgba(255,45,85,0.1); border-color: rgba(255,45,85,0.4); }}
  .sev-critical .sev-dot {{ background: #ff2d55; }}
  .sev-high {{ background: rgba(255,107,45,0.1); border-color: rgba(255,107,45,0.4); }}
  .sev-high .sev-dot {{ background: #ff6b2d; }}
  .sev-medium {{ background: rgba(240,192,64,0.1); border-color: rgba(240,192,64,0.4); }}
  .sev-medium .sev-dot {{ background: #f0c040; }}
  .sev-low {{ background: rgba(48,209,88,0.1); border-color: rgba(48,209,88,0.4); }}
  .sev-low .sev-dot {{ background: #30d158; }}

 
  
  .main-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 28px;
  }}
  .full-width {{ grid-column: 1 / -1; }}

  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px;
  }}
  .card-title {{
    font-size: 0.8rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
    margin-bottom: 18px;
    display: flex; align-items: center; gap: 8px;
  }}
  .card-title::before {{
    content: '';
    width: 3px; height: 14px;
    background: var(--accent);
    border-radius: 2px;
  }}


  .filter-bar {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 16px;
  }}
  .filter-bar input, .filter-bar select {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    padding: 8px 12px;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    outline: none;
    transition: border-color 0.2s;
  }}
  .filter-bar input:focus, .filter-bar select:focus {{ border-color: var(--accent); }}
  .filter-bar input {{ flex: 1; min-width: 200px; }}

  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-dim);
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  tbody tr {{
    border-bottom: 1px solid rgba(30,45,80,0.5);
    transition: background 0.15s;
    cursor: pointer;
  }}
  tbody tr:hover {{ background: var(--surface2); }}
  tbody td {{ padding: 10px 12px; font-size: 0.8rem; }}
  .badge {{
    display: inline-flex; align-items: center; gap: 4px;
    padding: 3px 8px; border-radius: 5px;
    font-family: var(--font-mono); font-size: 0.68rem; font-weight: 700;
  }}
  .badge-CRITICAL {{ background: rgba(255,45,85,0.2); color: #ff2d55; }}
  .badge-HIGH {{ background: rgba(255,107,45,0.2); color: #ff6b2d; }}
  .badge-MEDIUM {{ background: rgba(240,192,64,0.2); color: #f0c040; }}
  .badge-LOW {{ background: rgba(48,209,88,0.2); color: #30d158; }}
  .ip-tag {{
    font-family: var(--font-mono);
    font-size: 0.78rem;
    color: var(--accent);
    background: rgba(0,212,255,0.08);
    padding: 2px 6px;
    border-radius: 4px;
  }}
  .table-wrap {{ overflow-x: auto; max-height: 400px; overflow-y: auto; }}
  .table-wrap::-webkit-scrollbar {{ width: 5px; height: 5px; }}
  .table-wrap::-webkit-scrollbar-track {{ background: var(--surface2); }}
  .table-wrap::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}


  .bar-list {{ display: flex; flex-direction: column; gap: 10px; }}
  .bar-item {{ display: flex; flex-direction: column; gap: 4px; }}
  .bar-header {{ display: flex; justify-content: space-between; font-size: 0.75rem; }}
  .bar-ip {{ font-family: var(--font-mono); color: var(--accent); }}
  .bar-val {{ color: var(--text-dim); }}
  .bar-track {{ height: 5px; background: var(--surface2); border-radius: 3px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 3px; background: linear-gradient(90deg, var(--accent), var(--accent2)); transition: width 0.8s ease; }}

  
  .modal {{ display: none; position: fixed; inset: 0; z-index: 1000; background: rgba(10,14,26,0.9); backdrop-filter: blur(4px); }}
  .modal.open {{ display: flex; align-items: center; justify-content: center; }}
  .modal-box {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px;
    max-width: 560px; width: 90%;
    position: relative;
    animation: pop 0.2s ease;
  }}
  @keyframes pop {{ from {{ opacity:0; transform: scale(0.95); }} to {{ opacity:1; transform: scale(1); }} }}
  .modal-close {{
    position: absolute; top: 16px; right: 16px;
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); cursor: pointer;
    width: 32px; height: 32px; font-size: 1rem;
    display: flex; align-items: center; justify-content: center;
  }}
  .modal-title {{ font-size: 1rem; font-weight: 700; margin-bottom: 4px; }}
  .modal-subtitle {{ font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono); margin-bottom: 20px; }}
  .modal-detail {{ background: var(--surface2); border-radius: 10px; padding: 14px; font-family: var(--font-mono); font-size: 0.75rem; white-space: pre-wrap; word-break: break-all; }}

  .count-badge {{ display: inline-block; background: rgba(0,212,255,0.1); color: var(--accent); border-radius: 6px; padding: 2px 8px; font-family: var(--font-mono); font-size: 0.7rem; }}


  @media (max-width: 768px) {{
    .main-grid {{ grid-template-columns: 1fr; }}
    .sev-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
  }}

 
  .card, .stat-card, .sev-card {{
    animation: fadeUp 0.4s ease backwards;
  }}
  @keyframes fadeUp {{
    from {{ opacity: 0; transform: translateY(12px); }}
    to {{ opacity: 1; transform: translateY(0); }}
  }}
</style>
</head>
<body>

<div class="container">

  <header>
    <div class="header-inner">
      <div class="logo">
        <div class="logo-icon">🛡️</div>
        <div>
          <h1>Net<span>Watch</span></h1>
          <div style="font-size:0.7rem; color: var(--text-dim); font-family: var(--font-mono);">Network Intrusion Analysis System</div>
        </div>
      </div>
      <div class="header-meta">
        <div>Fichier : <strong>{meta.get('pcap_file', 'N/A')}</strong></div>
        <div>Généré le : <strong>{meta.get('generated_at', 'N/A')}</strong></div>
        <div>Durée capture : <strong>{stats.get('duration_seconds', 0)}s</strong></div>
      </div>
    </div>
  </header>

  <!-- Score risque -->
  <div class="risk-badge">
    <div class="risk-circle" style="border-color: {risk_color}; color: {risk_color};">
      <div class="score">{risk_score}</div>
      <div class="label">/ 100</div>
    </div>
    <div class="risk-info">
      <h2>Niveau de risque : <span style="color: {risk_color}">{risk_level}</span></h2>
      <p>
        {stats.get('total_alerts', 0)} alertes détectées ·
        {stats.get('unique_suspicious_ips', 0)} IPs suspectes ·
        {stats.get('total_packets', 0)} paquets analysés ·
        {stats.get('capture_start', 'N/A')} → {stats.get('capture_end', 'N/A')}
      </p>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card" style="animation-delay:0.05s">
      <div class="stat-icon">📦</div>
      <div class="stat-value">{stats.get('total_packets', 0):,}</div>
      <div class="stat-label">Paquets analysés</div>
    </div>
    <div class="stat-card" style="animation-delay:0.1s">
      <div class="stat-icon">🌐</div>
      <div class="stat-value">{stats.get('total_ips', 0)}</div>
      <div class="stat-label">IPs uniques</div>
    </div>
    <div class="stat-card" style="animation-delay:0.15s">
      <div class="stat-icon">🚨</div>
      <div class="stat-value" style="color: var(--red)">{stats.get('total_alerts', 0)}</div>
      <div class="stat-label">Alertes totales</div>
    </div>
    <div class="stat-card" style="animation-delay:0.2s">
      <div class="stat-icon">👤</div>
      <div class="stat-value" style="color: var(--orange)">{stats.get('unique_suspicious_ips', 0)}</div>
      <div class="stat-label">IPs suspectes</div>
    </div>
    <div class="stat-card" style="animation-delay:0.25s">
      <div class="stat-icon">⏱️</div>
      <div class="stat-value">{stats.get('duration_seconds', 0)}<span style="font-size:1rem">s</span></div>
      <div class="stat-label">Durée capture</div>
    </div>
  </div>

  <!-- Alertes sévérité -->
  <div class="sev-grid">
    <div class="sev-card sev-critical">
      <div class="sev-dot"></div>
      <div class="sev-info">
        <div class="count" id="cnt-critical">0</div>
        <div class="name">Critique</div>
      </div>
    </div>
    <div class="sev-card sev-high">
      <div class="sev-dot"></div>
      <div class="sev-info">
        <div class="count" id="cnt-high">0</div>
        <div class="name">Élevé</div>
      </div>
    </div>
    <div class="sev-card sev-medium">
      <div class="sev-dot"></div>
      <div class="sev-info">
        <div class="count" id="cnt-medium">0</div>
        <div class="name">Moyen</div>
      </div>
    </div>
    <div class="sev-card sev-low">
      <div class="sev-dot"></div>
      <div class="sev-info">
        <div class="count" id="cnt-low">0</div>
        <div class="name">Faible</div>
      </div>
    </div>
  </div>

  <!-- Graphiques -->
  <div class="main-grid">
    <div class="card">
      <div class="card-title">Répartition des protocoles</div>
      <canvas id="chartProtocols" height="200"></canvas>
    </div>
    <div class="card">
      <div class="card-title">Alertes par catégorie</div>
      <canvas id="chartCategories" height="200"></canvas>
    </div>
    <div class="card">
      <div class="card-title">Top ports ciblés</div>
      <canvas id="chartPorts" height="200"></canvas>
    </div>
    <div class="card">
      <div class="card-title">Top IPs — Volume de trafic</div>
      <div class="bar-list" id="talkersBar"></div>
    </div>
  </div>

  <!-- Tableau alertes -->
  <div class="card full-width">
    <div class="card-title">
      Alertes détaillées
      <span class="count-badge" id="alert-count">0</span>
    </div>
    <div class="filter-bar">
      <input type="text" id="filterText" placeholder="🔍  Rechercher IP, catégorie, description...">
      <select id="filterSev">
        <option value="">Toutes sévérités</option>
        <option value="CRITICAL">🔴 CRITICAL</option>
        <option value="HIGH">🟠 HIGH</option>
        <option value="MEDIUM">🟡 MEDIUM</option>
        <option value="LOW">🔵 LOW</option>
      </select>
      <select id="filterCat">
        <option value="">Toutes catégories</option>
      </select>
      <button onclick="exportCSV()" style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px 14px;border-radius:8px;cursor:pointer;font-family:var(--font-mono);font-size:0.78rem;">
        ⬇️ CSV
      </button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Sévérité</th>
            <th>Catégorie</th>
            <th>IP Source</th>
            <th>Description</th>
            <th>Horodatage</th>
          </tr>
        </thead>
        <tbody id="alertsTable"></tbody>
      </table>
    </div>
  </div>

</div>

<!-- Modal détail -->
<div class="modal" id="detailModal">
  <div class="modal-box">
    <button class="modal-close" onclick="closeModal()">✕</button>
    <div id="modal-sev" style="margin-bottom:8px"></div>
    <div class="modal-title" id="modal-title"></div>
    <div class="modal-subtitle" id="modal-subtitle"></div>
    <div class="modal-detail" id="modal-detail"></div>
  </div>
</div>

<script>
// Données injectées
const allAlerts = {alerts_json};
const protocolData = {protocol_json};
const topTalkers = {talkers_json};
const topPorts = {ports_json};
const alertsBySev = {sev_json};
const alertsByCat = {cat_json};

// Compteurs sévérité 
document.getElementById('cnt-critical').textContent = alertsBySev['CRITICAL'] || 0;
document.getElementById('cnt-high').textContent = alertsBySev['HIGH'] || 0;
document.getElementById('cnt-medium').textContent = alertsBySev['MEDIUM'] || 0;
document.getElementById('cnt-low').textContent = alertsBySev['LOW'] || 0;

//Options Chart.js communes 
const chartDefaults = {{
  plugins: {{
    legend: {{ labels: {{ color: '#94a3b8', font: {{ family: 'JetBrains Mono', size: 11 }} }} }},
    tooltip: {{ backgroundColor: '#141e35', titleColor: '#e2e8f0', bodyColor: '#94a3b8',
                borderColor: '#1e2d50', borderWidth: 1 }}
  }},
  scales: {{
    x: {{ ticks: {{ color: '#64748b', font: {{ family: 'JetBrains Mono', size: 10 }} }},
         grid: {{ color: 'rgba(30,45,80,0.5)' }} }},
    y: {{ ticks: {{ color: '#64748b', font: {{ family: 'JetBrains Mono', size: 10 }} }},
         grid: {{ color: 'rgba(30,45,80,0.5)' }} }}
  }}
}};

// Graphique protocoles 
const protoLabels = Object.keys(protocolData);
const protoValues = Object.values(protocolData);
const protoColors = ['#00d4ff','#7c3aed','#30d158','#f0c040','#ff6b2d','#ff2d55'];
new Chart(document.getElementById('chartProtocols'), {{
  type: 'doughnut',
  data: {{
    labels: protoLabels,
    datasets: [{{ data: protoValues, backgroundColor: protoColors.slice(0, protoLabels.length),
                  borderWidth: 2, borderColor: '#0f1729' }}]
  }},
  options: {{
    cutout: '65%',
    plugins: chartDefaults.plugins,
    animation: {{ animateRotate: true, duration: 800 }}
  }}
}});

// graphique catégories 
const catLabels = Object.keys(alertsByCat);
const catValues = Object.values(alertsByCat);
new Chart(document.getElementById('chartCategories'), {{
  type: 'bar',
  data: {{
    labels: catLabels,
    datasets: [{{
      data: catValues,
      backgroundColor: 'rgba(124,58,237,0.7)',
      borderColor: '#7c3aed',
      borderWidth: 1,
      borderRadius: 4,
    }}]
  }},
  options: {{ ...chartDefaults, plugins: chartDefaults.plugins, indexAxis: 'y',
    scales: {{ x: chartDefaults.scales.x, y: chartDefaults.scales.y }},
    animation: {{ duration: 800 }}
  }}
}});

//graphique ports 
if (topPorts.length > 0) {{
  const portLabels = topPorts.map(p => `${{p.port}} (${{p.service}})`);
  const portValues = topPorts.map(p => p.count);
  new Chart(document.getElementById('chartPorts'), {{
    type: 'bar',
    data: {{
      labels: portLabels,
      datasets: [{{
        data: portValues,
        backgroundColor: portValues.map((_, i) =>
          i < 3 ? 'rgba(255,45,85,0.7)' : 'rgba(0,212,255,0.5)'),
        borderColor: portValues.map((_, i) =>
          i < 3 ? '#ff2d55' : '#00d4ff'),
        borderWidth: 1, borderRadius: 4
      }}]
    }},
    options: {{ ...chartDefaults, animation: {{ duration: 800 }} }}
  }});
}}

// Top Talkers barre
if (topTalkers.length > 0) {{
  const maxBytes = topTalkers[0].bytes;
  const container = document.getElementById('talkersBar');
  topTalkers.forEach(t => {{
    const pct = Math.round((t.bytes / maxBytes) * 100);
    container.innerHTML += `
      <div class="bar-item">
        <div class="bar-header">
          <span class="bar-ip">${{t.ip}}</span>
          <span class="bar-val">${{t.kb}} KB</span>
        </div>
        <div class="bar-track"><div class="bar-fill" style="width: ${{pct}}%"></div></div>
      </div>`;
  }});
}}

//Tableau alertes 
const sevIcons = {{ CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🔵' }};

// Rempli filtre catégories
const uniqueCats = [...new Set(allAlerts.map(a => a.category))];
const catSelect = document.getElementById('filterCat');
uniqueCats.forEach(c => {{
  const opt = document.createElement('option');
  opt.value = c; opt.textContent = c;
  catSelect.appendChild(opt);
}});

function renderTable(alerts) {{
  const tbody = document.getElementById('alertsTable');
  document.getElementById('alert-count').textContent = alerts.length;
  if (alerts.length === 0) {{
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:24px;">Aucune alerte correspondante</td></tr>';
    return;
  }}
  tbody.innerHTML = alerts.map(a => `
    <tr onclick="showDetail(${{a.id - 1}})">
      <td style="color:var(--text-dim);font-family:var(--font-mono)">#${{a.id}}</td>
      <td><span class="badge badge-${{a.severity}}">${{sevIcons[a.severity]}} ${{a.severity}}</span></td>
      <td style="color:var(--text)">${{a.category}}</td>
      <td><span class="ip-tag">${{a.src_ip}}</span></td>
      <td style="color:var(--text-dim)">${{a.description}}</td>
      <td style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.7rem">${{a.timestamp}}</td>
    </tr>`).join('');
}}

function filterAlerts() {{
  const text = document.getElementById('filterText').value.toLowerCase();
  const sev = document.getElementById('filterSev').value;
  const cat = document.getElementById('filterCat').value;
  return allAlerts.filter(a => {{
    const matchText = !text || a.src_ip.includes(text) ||
      a.category.toLowerCase().includes(text) || a.description.toLowerCase().includes(text);
    const matchSev = !sev || a.severity === sev;
    const matchCat = !cat || a.category === cat;
    return matchText && matchSev && matchCat;
  }});
}}

document.getElementById('filterText').addEventListener('input', () => renderTable(filterAlerts()));
document.getElementById('filterSev').addEventListener('change', () => renderTable(filterAlerts()));
document.getElementById('filterCat').addEventListener('change', () => renderTable(filterAlerts()));

renderTable(allAlerts);

// Modal détail
function showDetail(idx) {{
  const a = allAlerts[idx];
  document.getElementById('modal-sev').innerHTML =
    `<span class="badge badge-${{a.severity}}">${{sevIcons[a.severity]}} ${{a.severity}}</span>`;
  document.getElementById('modal-title').textContent = `${{a.category}} — ${{a.src_ip}}`;
  document.getElementById('modal-subtitle').textContent = `${{a.timestamp}} · Alerte #${{a.id}}`;
  document.getElementById('modal-detail').textContent =
    `Description :\n${{a.description}}\n\nDétails techniques :\n${{JSON.stringify(a.details, null, 2)}}`;
  document.getElementById('detailModal').classList.add('open');
}}
function closeModal() {{
  document.getElementById('detailModal').classList.remove('open');
}}
document.getElementById('detailModal').addEventListener('click', e => {{
  if (e.target.id === 'detailModal') closeModal();
}});

//export CSV
function exportCSV() {{
  const filtered = filterAlerts();
  const header = ['ID','Sévérité','Catégorie','IP Source','Description','Horodatage'];
  const rows = filtered.map(a => [a.id, a.severity, a.category, a.src_ip,
    `"${{a.description.replace(/"/g,'""')}}"`, a.timestamp]);
  const csv = [header, ...rows].map(r => r.join(',')).join('\\n');
  const blob = new Blob([csv], {{type:'text/csv;charset=utf-8;'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'netwatch_alerts.csv'; a.click();
  URL.revokeObjectURL(url);
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Dashboard HTML généré : {output_path}")
    print(f"    → Ouvrir ce fichier dans ton navigateur pour visualiser le rapport.")
    return output_path



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Génère le dashboard HTML NetWatch")
    parser.add_argument("-i", "--input", default="netwatch_report.json",
                        help="Fichier JSON généré par netwatch.py")
    parser.add_argument("-o", "--output", default="netwatch_dashboard.html",
                        help="Fichier HTML de sortie")
    args = parser.parse_args()

    json_path = Path(args.input)
    if not json_path.exists():
        print(f"[!] Fichier JSON introuvable : {json_path}")
        print("    Lancer d'abord : python netwatch.py --demo")
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    generate_html_report(report, args.output)
