#!/usr/bin/env python3

import json
import sys
from pathlib import Path

def generer_dashboard(rapport: dict, sortie: str = "dashboard.html"):

    infos   = rapport.get("infos", {})
    alertes = rapport.get("alertes", [])
    score   = rapport.get("score", 0)
    niveau  = rapport.get("niveau", "FAIBLE")
    top_ips = rapport.get("top_ips", [])
    protos  = infos.get("protocoles", {})

    couleur_niveau = {
        "CRITIQUE": "#ef4444",
        "ELEVE"   : "#f97316",
        "MOYEN"   : "#eab308",
        "FAIBLE"  : "#22c55e"
    }.get(niveau, "#22c55e")

    nb_critique = sum(1 for a in alertes if a["severite"] == "CRITIQUE")
    nb_eleve    = sum(1 for a in alertes if a["severite"] == "ELEVE")
    nb_moyen    = sum(1 for a in alertes if a["severite"] == "MOYEN")

    alertes_json = json.dumps(alertes, ensure_ascii=False)
    protos_json  = json.dumps(protos)
    ips_json     = json.dumps(top_ips)

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetWatch - Rapport d'analyse</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

:root {{
  --bg       : #f8fafc;
  --surface  : #ffffff;
  --border   : #e2e8f0;
  --text     : #0f172a;
  --text-dim : #64748b;
  --accent   : #2563eb;
  --mono     : 'IBM Plex Mono', monospace;
  --sans     : 'IBM Plex Sans', sans-serif;
}}

body {{
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}}

/* ── Header ── */
.header {{
  background: var(--text);
  color: white;
  padding: 18px 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}}
.header-logo {{
  display: flex;
  align-items: center;
  gap: 10px;
}}
.header-logo .icon {{
  width: 36px; height: 36px;
  background: var(--accent);
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 18px;
}}
.header-logo h1 {{
  font-size: 1.3rem;
  font-weight: 700;
  letter-spacing: -0.3px;
}}
.header-logo h1 span {{ color: #60a5fa; }}
.header-meta {{
  font-family: var(--mono);
  font-size: 0.72rem;
  color: #94a3b8;
  text-align: right;
  line-height: 1.8;
}}
.header-meta strong {{ color: white; }}

/* ── Contenu ── */
.content {{
  max-width: 1100px;
  margin: 0 auto;
  padding: 28px 24px;
}}

/* ── Bandeau de risque ── */
.risk-banner {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 4px solid {couleur_niveau};
  border-radius: 10px;
  padding: 20px 24px;
  display: flex;
  align-items: center;
  gap: 20px;
  margin-bottom: 24px;
}}
.risk-score {{
  font-family: var(--mono);
  font-size: 2.8rem;
  font-weight: 600;
  color: {couleur_niveau};
  line-height: 1;
  flex-shrink: 0;
}}
.risk-score span {{
  font-size: 1rem;
  color: var(--text-dim);
}}
.risk-text h2 {{
  font-size: 1.1rem;
  font-weight: 600;
  color: {couleur_niveau};
}}
.risk-text p {{
  font-size: 0.82rem;
  color: var(--text-dim);
  margin-top: 4px;
  font-family: var(--mono);
}}

/* ── Grille de stats ── */
.stats-row {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  margin-bottom: 24px;
}}
.stat {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px 20px;
}}
.stat .val {{
  font-family: var(--mono);
  font-size: 1.9rem;
  font-weight: 600;
  line-height: 1;
}}
.stat .lbl {{
  font-size: 0.72rem;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 6px;
}}

/* ── Badges sévérité ── */
.sev-row {{
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 14px;
  margin-bottom: 24px;
}}
.sev-card {{
  border-radius: 10px;
  padding: 16px 20px;
  border: 1px solid;
}}
.sev-card .nb {{
  font-family: var(--mono);
  font-size: 2.2rem;
  font-weight: 600;
  line-height: 1;
}}
.sev-card .nom {{
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: 4px;
  opacity: 0.7;
}}
.sev-critique {{ background: #fef2f2; border-color: #fca5a5; color: #dc2626; }}
.sev-eleve    {{ background: #fff7ed; border-color: #fdba74; color: #ea580c; }}
.sev-moyen    {{ background: #fefce8; border-color: #fde047; color: #ca8a04; }}

/* ── Grille principale ── */
.main-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 24px;
}}
.card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
}}
.card-title {{
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  color: var(--text-dim);
  margin-bottom: 16px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}}

/* ── Tableau alertes ── */
.alertes-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 24px;
}}
.alertes-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}}
.alertes-header .card-title {{ margin: 0; padding: 0; border: none; }}
.count-pill {{
  background: #eff6ff;
  color: var(--accent);
  font-family: var(--mono);
  font-size: 0.72rem;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 20px;
}}

/* Filtre */
.filtre-bar {{
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}}
.filtre-bar input, .filtre-bar select {{
  font-family: var(--sans);
  font-size: 0.82rem;
  padding: 7px 12px;
  border: 1px solid var(--border);
  border-radius: 7px;
  background: var(--bg);
  color: var(--text);
  outline: none;
}}
.filtre-bar input {{ flex: 1; min-width: 200px; }}
.filtre-bar input:focus, .filtre-bar select:focus {{ border-color: var(--accent); }}
.btn-csv {{
  font-family: var(--sans);
  font-size: 0.82rem;
  padding: 7px 14px;
  border: 1px solid var(--border);
  border-radius: 7px;
  background: var(--bg);
  color: var(--text);
  cursor: pointer;
  transition: background 0.15s;
}}
.btn-csv:hover {{ background: var(--border); }}

table {{ width: 100%; border-collapse: collapse; }}
thead th {{
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-dim);
  padding: 8px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  font-weight: 600;
}}
tbody tr {{
  border-bottom: 1px solid #f1f5f9;
  cursor: pointer;
  transition: background 0.1s;
}}
tbody tr:hover {{ background: #f8fafc; }}
tbody tr:last-child {{ border-bottom: none; }}
tbody td {{ padding: 10px 12px; font-size: 0.82rem; }}

.badge {{
  display: inline-block;
  font-family: var(--mono);
  font-size: 0.68rem;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 4px;
}}
.badge-CRITIQUE {{ background: #fef2f2; color: #dc2626; }}
.badge-ELEVE    {{ background: #fff7ed; color: #ea580c; }}
.badge-MOYEN    {{ background: #fefce8; color: #ca8a04; }}
.ip {{ font-family: var(--mono); font-size: 0.78rem; color: var(--accent); }}

/* ── Top IPs barres ── */
.bars {{ display: flex; flex-direction: column; gap: 12px; }}
.bar-item {{ display: flex; flex-direction: column; gap: 5px; }}
.bar-top {{ display: flex; justify-content: space-between; font-size: 0.75rem; }}
.bar-ip {{ font-family: var(--mono); color: var(--accent); }}
.bar-ko {{ color: var(--text-dim); }}
.bar-bg {{ height: 6px; background: #f1f5f9; border-radius: 3px; overflow: hidden; }}
.bar-fill {{ height: 100%; background: var(--accent); border-radius: 3px; transition: width 0.6s ease; }}

/* ── Modal ── */
.modal {{
  display: none;
  position: fixed; inset: 0; z-index: 100;
  background: rgba(15,23,42,0.5);
  backdrop-filter: blur(2px);
  align-items: center; justify-content: center;
}}
.modal.open {{ display: flex; }}
.modal-box {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  max-width: 480px; width: 90%;
  position: relative;
  animation: pop 0.15s ease;
}}
@keyframes pop {{ from {{ opacity:0;transform:scale(.96) }} to {{ opacity:1;transform:scale(1) }} }}
.modal-close {{
  position: absolute; top: 14px; right: 14px;
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 6px; cursor: pointer;
  width: 28px; height: 28px; font-size: 0.9rem;
  color: var(--text-dim);
}}
.modal-type {{ font-size: 1rem; font-weight: 700; margin: 8px 0 2px; }}
.modal-ip {{ font-family: var(--mono); font-size: 0.8rem; color: var(--accent); margin-bottom: 14px; }}
.modal-desc {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--text-dim);
  line-height: 1.6;
}}

@media (max-width: 700px) {{
  .stats-row {{ grid-template-columns: repeat(2,1fr); }}
  .sev-row   {{ grid-template-columns: repeat(3,1fr); }}
  .main-grid {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div class="header-logo">
    <div class="icon">🛡️</div>
    <h1>Net<span>Watch</span></h1>
  </div>
  <div class="header-meta">
    <div>Fichier : <strong>{infos.get('fichier','N/A')}</strong></div>
    <div>Généré le : <strong>{rapport.get('genere_le','N/A')}</strong></div>
  </div>
</div>

<div class="content">

  <!-- Bandeau risque -->
  <div class="risk-banner">
    <div class="risk-score">{score}<span>/100</span></div>
    <div class="risk-text">
      <h2>Niveau de risque : {niveau}</h2>
      <p>
        {infos.get('total_paquets',0):,} paquets analysés ·
        {infos.get('total_ips',0)} IPs détectées ·
        {infos.get('duree_secondes',0)}s de capture ·
        {infos.get('debut','N/A')} → {infos.get('fin','N/A')}
      </p>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-row">
    <div class="stat">
      <div class="val">{infos.get('total_paquets',0):,}</div>
      <div class="lbl">Paquets analysés</div>
    </div>
    <div class="stat">
      <div class="val">{infos.get('total_ips',0)}</div>
      <div class="lbl">IPs détectées</div>
    </div>
    <div class="stat">
      <div class="val" style="color:#ef4444">{len(alertes)}</div>
      <div class="lbl">Alertes totales</div>
    </div>
    <div class="stat">
      <div class="val">{infos.get('duree_secondes',0)}s</div>
      <div class="lbl">Durée capture</div>
    </div>
  </div>

  <!-- Sévérités -->
  <div class="sev-row">
    <div class="sev-card sev-critique">
      <div class="nb" id="nb-critique">0</div>
      <div class="nom">Critique</div>
    </div>
    <div class="sev-card sev-eleve">
      <div class="nb" id="nb-eleve">0</div>
      <div class="nom">Élevé</div>
    </div>
    <div class="sev-card sev-moyen">
      <div class="nb" id="nb-moyen">0</div>
      <div class="nom">Moyen</div>
    </div>
  </div>

  <!-- Graphiques -->
  <div class="main-grid">
    <div class="card">
      <div class="card-title">Protocoles réseau</div>
      <canvas id="chartProto" height="200"></canvas>
    </div>
    <div class="card">
      <div class="card-title">Top IPs — volume de trafic</div>
      <div class="bars" id="barsIPs"></div>
    </div>
  </div>

  <!-- Tableau alertes -->
  <div class="alertes-card">
    <div class="alertes-header">
      <div class="card-title">Alertes détectées</div>
      <span class="count-pill" id="compteur">0</span>
    </div>
    <div class="filtre-bar">
      <input type="text" id="recherche" placeholder="Rechercher une IP, un type...">
      <select id="filtreSev">
        <option value="">Toutes sévérités</option>
        <option value="CRITIQUE">CRITIQUE</option>
        <option value="ELEVE">ÉLEVÉ</option>
        <option value="MOYEN">MOYEN</option>
      </select>
      <button class="btn-csv" onclick="exportCSV()">⬇ Export CSV</button>
    </div>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Sévérité</th>
          <th>Type</th>
          <th>IP source</th>
          <th>Description</th>
          <th>Heure</th>
        </tr>
      </thead>
      <tbody id="tableau"></tbody>
    </table>
  </div>

</div>

<div class="modal" id="modal">
  <div class="modal-box">
    <button class="modal-close" onclick="fermerModal()">✕</button>
    <div id="modal-badge"></div>
    <div class="modal-type" id="modal-type"></div>
    <div class="modal-ip" id="modal-ip"></div>
    <div class="modal-desc" id="modal-desc"></div>
  </div>
</div>

<script>
const alertes = {alertes_json};
const protos  = {protos_json};
const topIPs  = {ips_json};

// Compteurs sévérité
document.getElementById('nb-critique').textContent = alertes.filter(a=>a.severite==='CRITIQUE').length;
document.getElementById('nb-eleve').textContent    = alertes.filter(a=>a.severite==='ELEVE').length;
document.getElementById('nb-moyen').textContent    = alertes.filter(a=>a.severite==='MOYEN').length;

// Graphique protocoles
const labels = Object.keys(protos);
const vals   = Object.values(protos);
const colors = ['#2563eb','#7c3aed','#0891b2','#059669','#d97706'];
new Chart(document.getElementById('chartProto'), {{
  type: 'doughnut',
  data: {{
    labels,
    datasets: [{{
      data: vals,
      backgroundColor: colors.slice(0, labels.length),
      borderWidth: 2,
      borderColor: '#ffffff'
    }}]
  }},
  options: {{
    cutout: '60%',
    plugins: {{
      legend: {{
        labels: {{ font: {{ family: 'IBM Plex Sans', size: 12 }}, color: '#64748b' }}
      }}
    }}
  }}
}});

// Barres top IPs
if (topIPs.length > 0) {{
  const max = topIPs[0].ko;
  const cont = document.getElementById('barsIPs');
  topIPs.forEach(t => {{
    const pct = Math.round((t.ko / max) * 100);
    cont.innerHTML += `
      <div class="bar-item">
        <div class="bar-top">
          <span class="bar-ip">${{t.ip}}</span>
          <span class="bar-ko">${{t.ko}} KB</span>
        </div>
        <div class="bar-bg"><div class="bar-fill" style="width:${{pct}}%"></div></div>
      </div>`;
  }});
}}

// Tableau
function afficherTableau(liste) {{
  document.getElementById('compteur').textContent = liste.length;
  const tbody = document.getElementById('tableau');
  if (!liste.length) {{
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:20px;color:#94a3b8">Aucune alerte</td></tr>';
    return;
  }}
  tbody.innerHTML = liste.map(a => `
    <tr onclick="ouvrirModal(${{a.id-1}})">
      <td style="color:#94a3b8;font-family:var(--mono)">#${{a.id}}</td>
      <td><span class="badge badge-${{a.severite}}">${{a.severite}}</span></td>
      <td>${{a.type}}</td>
      <td><span class="ip">${{a.ip}}</span></td>
      <td style="color:#475569">${{a.description}}</td>
      <td style="color:#94a3b8;font-family:var(--mono);font-size:0.72rem">${{a.heure}}</td>
    </tr>`).join('');
}}

function filtrer() {{
  const txt = document.getElementById('recherche').value.toLowerCase();
  const sev = document.getElementById('filtreSev').value;
  return alertes.filter(a =>
    (!txt || a.ip.includes(txt) || a.type.toLowerCase().includes(txt) || a.description.toLowerCase().includes(txt)) &&
    (!sev || a.severite === sev)
  );
}}

document.getElementById('recherche').addEventListener('input', () => afficherTableau(filtrer()));
document.getElementById('filtreSev').addEventListener('change', () => afficherTableau(filtrer()));
afficherTableau(alertes);

function ouvrirModal(i) {{
  const a = alertes[i];
  document.getElementById('modal-badge').innerHTML = `<span class="badge badge-${{a.severite}}">${{a.severite}}</span>`;
  document.getElementById('modal-type').textContent = a.type;
  document.getElementById('modal-ip').textContent   = a.ip;
  document.getElementById('modal-desc').textContent = a.description + '\\n\\nHeure : ' + a.heure;
  document.getElementById('modal').classList.add('open');
}}
function fermerModal() {{
  document.getElementById('modal').classList.remove('open');
}}
document.getElementById('modal').addEventListener('click', e => {{
  if (e.target.id === 'modal') fermerModal();
}});

// Export CSV
function exportCSV() {{
  const data = filtrer();
  const csv  = ['ID,Sévérité,Type,IP,Description,Heure',
    ...data.map(a => `${{a.id}},${{a.severite}},${{a.type}},${{a.ip}},"${{a.description}}",${{a.heure}}`)
  ].join('\\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], {{type:'text/csv'}}));
  a.download = 'alertes.csv';
  a.click();
}}
</script>
</body>
</html>"""

    with open(sortie, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Dashboard généré : {sortie}")
    print(f"    → Ouvre {sortie} dans ton navigateur.")

if __name__ == "__main__":
    chemin = Path("rapport.json")
    if not chemin.exists():
        print("[!] rapport.json introuvable.")
        print("    Lance d'abord : python netwatch.py --demo")
        sys.exit(1)

    with open(chemin, "r", encoding="utf-8") as f:
        rapport = json.load(f)

    generer_dashboard(rapport)
