# 🛡️ NetWatch — Analyseur de captures réseau PCAP

> Projet Licence Informatique Cybersécurité  
> Détection d'anomalies et d'intrusions réseau avec dashboard interactif

---

## 📁 Structure du projet

```
netwatch/
├── netwatch.py          ← Script principal d'analyse
├── generate_report.py   ← Générateur de dashboard HTML
├── README.md            ← Ce fichier
└── captures/            ← Dossier pour tes fichiers .pcap (à créer)
```

---

## ⚙️ Installation

```bash
# Cloner / télécharger le projet
# Installer les dépendances
pip install scapy

# Sur Linux, scapy nécessite les droits root pour capturer en live
# Pour lire des fichiers .pcap existants, pas besoin de sudo
```

---

## 🚀 Utilisation

### Mode démonstration (sans fichier PCAP)
```bash
python netwatch.py --demo --export-html
python generate_report.py
# Ouvre netwatch_dashboard.html dans ton navigateur
```

### Analyser un fichier PCAP réel
```bash
python netwatch.py -f capture.pcap --export-html --export-csv
python generate_report.py -i netwatch_report.json -o mon_rapport.html
```

### Filtrer les alertes en ligne de commande
```bash
# Afficher uniquement les alertes critiques
python netwatch.py -f capture.pcap --filter-severity CRITICAL

# Filtrer par IP suspecte
python netwatch.py -f capture.pcap --filter-ip 192.168.1.50

# Mode verbeux (détail de chaque alerte)
python netwatch.py -f capture.pcap --verbose
```

### Générer un rapport dans un dossier spécifique
```bash
python netwatch.py --demo --output-dir ./rapports/
```

---

## 🔍 Menaces détectées

| Type d'attaque        | Méthode de détection                          | Sévérité |
|-----------------------|-----------------------------------------------|----------|
| **Scan de ports**     | > 15 ports distincts depuis une même IP       | HIGH/CRITICAL |
| **SYN Flood**         | > 100 paquets SYN sans complétion handshake   | CRITICAL |
| **Brute Force SSH**   | > 10 tentatives sur port 22                   | HIGH/CRITICAL |
| **Brute Force RDP**   | > 10 tentatives sur port 3389                 | HIGH |
| **ARP Spoofing**      | Une IP associée à > 5 adresses MAC            | HIGH |
| **ICMP Flood**        | > 50 paquets ICMP depuis une IP               | MEDIUM |
| **DNS Tunneling**     | > 30 requêtes DNS avec domaines très variés   | MEDIUM |
| **Port sensible**     | Connexion vers Telnet, Redis, MongoDB, VNC... | MEDIUM |

---

## 📊 Fonctionnalités du dashboard

- **Score de risque** (0-100) calculé selon les alertes
- **Graphique protocoles** (TCP, UDP, ICMP, DNS, ARP)
- **Top ports ciblés** (histogramme)
- **Top IPs actives** (volume de trafic en KB)
- **Tableau filtrable** par sévérité, catégorie, IP, texte libre
- **Modal détail** au clic sur chaque alerte
- **Export CSV** directement depuis l'interface

---

## 🎓 Concepts cybersécurité abordés

- **Analyse de trafic réseau** (PCAP, Wireshark)
- **Détection d'intrusion** (IDS — Intrusion Detection System)
- **Protocoles réseau** : TCP/IP, UDP, ICMP, ARP, DNS
- **Attaques classiques** : Scan de ports, SYN Flood, Brute Force, ARP Spoofing
- **Analyse comportementale** : détection par seuils et ratios
- **Score de risque** : évaluation quantitative de la menace

---

## 📦 Dépendances

| Bibliothèque | Usage               | Installation         |
|--------------|---------------------|----------------------|
| `scapy`      | Analyse PCAP        | `pip install scapy`  |
| `json`       | Export rapport      | stdlib               |
| `csv`        | Export alertes      | stdlib               |
| `argparse`   | CLI                 | stdlib               |
| `Chart.js`   | Graphiques (HTML)   | CDN (auto)           |

---

## 💡 Pour aller plus loin (amélioration du projet)

1. **Machine Learning** : classifier les anomalies avec `scikit-learn`
2. **Capture en live** : utiliser `scapy.sniff()` pour analyser en temps réel
3. **Base de données** : stocker l'historique avec `SQLite`
4. **Alertes email** : notifier via `smtplib` quand une attaque est détectée
5. **Intégration VirusTotal** : vérifier les IPs suspectes via l'API publique
6. **Corrélation temporelle** : détecter des attaques étalées dans le temps

---

## 🧪 Obtenir des fichiers PCAP de test

- **Wireshark Sample Captures** : https://wiki.wireshark.org/SampleCaptures
- **Malware Traffic Analysis** : https://www.malware-traffic-analysis.net
- **PCAP Zoo** : https://github.com/markofu/pcaps
- **Capturer soi-même** : `sudo tcpdump -w capture.pcap -i eth0`
