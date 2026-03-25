# NetWatch - Analyseur de captures réseau PCAP

Projet Licence Informatique Cybersécurité  
Détection d'anomalies et d'intrusions réseau avec dashboard interactif


--- 

## Installation

```bash
# Cloner / télécharger le projet
# Installer les dépendances
pip install scapy

```

---

## Utilisation

### Mode démonstration (sans fichier PCAP)
```bash
python netwatch.py --demo --export-html
python generate_report.py
# Ouvrir netwatch_dashboard.html dans un navigateur
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

# Mode détails
python netwatch.py -f capture.pcap --verbose
```

### Générer un rapport dans un dossier spécifique
```bash
python netwatch.py --demo --output-dir ./rapports/
```

---

## Menaces détectées

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

