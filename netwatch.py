#!/usr/bin/env python3

import json
import csv
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[!] scapy non installe -> pip install scapy")

SEUILS = {
    "scan_ports": 15,
    "syn_flood": 100,
    "brute_force": 10,
    "icmp_flood": 50,
    "dns_suspect": 30,
}

PORTS_SENSIBLES = {
    22: "SSH", 23: "Telnet", 21: "FTP",
    3389: "RDP", 445: "SMB", 3306: "MySQL",
    6379: "Redis", 5900: "VNC", 80: "HTTP", 443: "HTTPS"
}


class NetWatch:

  def __init__(self, fichier):
    self.fichier = fichier
    self.paquets = []
    self.alertes = []
    self.infos = {}
    self.ports_vus = defaultdict(set)
    self.compteur_syn = defaultdict(int)
    self.tentatives = defaultdict(Counter)
    self.table_arp = defaultdict(set)
    self.nb_pings = defaultdict(int)
    self.requetes_dns = defaultdict(list)
    self.trafic = defaultdict(int)
    self.protos = Counter()

  def charger(self):
    if not SCAPY_OK:
      return False
    f = Path(self.fichier)
    if not f.exists():
      print(f"[!] Fichier introuvable : {self.fichier}")
      return False
    print(f"[*] Lecture de {f.name}...")
    try:
      self.paquets = rdpcap(str(f))
      print(f"[+] {len(self.paquets)} paquets charges.")
      return True
    except Exception as e:
      print(f"[!] Erreur : {e}")
      return False

  def analyser(self):
    print("[*] Analyse en cours...")
    if not self.paquets:
      return

    debut = float(self.paquets[0].time)
    fin = float(self.paquets[-1].time)

    for p in self.paquets:
      if not p.haslayer(IP):
        continue

      src = p[IP].src
      self.trafic[src] += len(p)

      if p.haslayer(TCP):
        dport = p[TCP].dport
        self.protos["TCP"] += 1
        self.ports_vus[src].add(dport)
        self.tentatives[src][dport] += 1
        if p[TCP].flags == 0x02:
          self.compteur_syn[src] += 1

      elif p.haslayer(UDP):
        self.protos["UDP"] += 1
        self.ports_vus[src].add(p[UDP].dport)
        if p.haslayer(DNS) and p[DNS].qr == 0:
          self.protos["DNS"] += 1
          try:
            self.requetes_dns[src].append(p[DNS].qd.qname.decode())
          except:
            pass

      elif p.haslayer(ICMP):
        self.protos["ICMP"] += 1
        self.nb_pings[src] += 1

      if p.haslayer(ARP):
        self.protos["ARP"] += 1
        if p[ARP].op == 2:
          self.table_arp[p[ARP].psrc].add(p[ARP].hwsrc)

    self.infos = {
      "fichier": self.fichier,
      "debut": datetime.fromtimestamp(debut).strftime("%Y-%m-%d %H:%M:%S"),
      "fin": datetime.fromtimestamp(fin).strftime("%Y-%m-%d %H:%M:%S"),
      "duree_secondes": round(fin - debut, 2),
      "total_paquets": len(self.paquets),
      "total_ips": len(self.trafic),
      "protocoles": dict(self.protos),
    }
    print("[+] Analyse terminee.")

  def detecter(self):
    print("[*] Recherche de menaces...")

    for ip, ports in self.ports_vus.items():
      nb = len(ports)
      if nb >= SEUILS["scan_ports"]:
        sev = "CRITIQUE" if nb > 50 else "ELEVE"
        self._alerte(sev, "Scan de ports", ip, f"Scan de {nb} ports distincts detecte")

    for ip, nb in self.compteur_syn.items():
      if nb >= SEUILS["syn_flood"]:
        self._alerte("CRITIQUE", "SYN Flood", ip, f"{nb} paquets SYN sans handshake complet")

    for ip, cpt in self.tentatives.items():
      for port, nb in cpt.items():
        if port in PORTS_SENSIBLES and nb >= SEUILS["brute_force"]:
          self._alerte("ELEVE", "Brute Force", ip,
            f"{nb} tentatives sur port {port} ({PORTS_SENSIBLES[port]})")

    for ip, macs in self.table_arp.items():
      if len(macs) >= 3:
        self._alerte("ELEVE", "ARP Spoofing", ip,
          f"IP {ip} vue avec {len(macs)} adresses MAC differentes")

    for ip, nb in self.nb_pings.items():
      if nb >= SEUILS["icmp_flood"]:
        self._alerte("MOYEN", "ICMP Flood", ip, f"{nb} paquets ICMP envoyes")

    for ip, domaines in self.requetes_dns.items():
      if len(domaines) >= SEUILS["dns_suspect"]:
        u = len(set(domaines))
        self._alerte("MOYEN", "DNS Suspect", ip,
          f"{len(domaines)} requetes DNS, {u} domaines differents")

    print(f"[+] {len(self.alertes)} alerte(s) trouvee(s).")

  def _alerte(self, sev, type_att, ip, desc):
    self.alertes.append({
      "id": len(self.alertes) + 1,
      "severite": sev,
      "type": type_att,
      "ip": ip,
      "description": desc,
      "heure": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

  def score(self):
    total = 0
    for a in self.alertes:
      if a["severite"] == "CRITIQUE":
        total += 30
      elif a["severite"] == "ELEVE":
        total += 15
      elif a["severite"] == "MOYEN":
        total += 5
    s = min(100, total)
    if s >= 75:
      niv = "CRITIQUE"
    elif s >= 50:
      niv = "ELEVE"
    elif s >= 25:
      niv = "MOYEN"
    else:
      niv = "FAIBLE"
    return s, niv

  def top_ips(self):
    trie = sorted(self.trafic.items(), key=lambda x: x[1], reverse=True)
    result = []
    for ip, octets in trie[:8]:
      result.append({"ip": ip, "ko": round(octets / 1024, 1)})
    return result

  def afficher(self):
    s, niv = self.score()
    print("\n" + "-" * 46)
    print("  NETWATCH - RESULTATS")
    print("-" * 46)
    print(f"  Fichier  : {self.fichier}")
    print(f"  Paquets  : {self.infos.get('total_paquets', 0)}")
    print(f"  IPs      : {self.infos.get('total_ips', 0)}")
    print(f"  Duree    : {self.infos.get('duree_secondes', 0)}s")
    print(f"  Score    : {s}/100 - {niv}")
    print(f"  Alertes  : {len(self.alertes)}")
    for a in self.alertes:
      print(f"    [{a['severite']}] {a['type']} - {a['ip']}")
    print("-" * 46)

  def sauvegarder(self):
    s, niv = self.score()
    data = {
      "infos": self.infos,
      "score": s,
      "niveau": niv,
      "alertes": self.alertes,
      "top_ips": self.top_ips(),
      "genere_le": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open("rapport.json", "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2, ensure_ascii=False)
    print("[+] rapport.json sauvegarde.")
    if self.alertes:
      with open("alertes.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id","severite","type","ip","description","heure"])
        writer.writeheader()
        writer.writerows(self.alertes)
      print("[+] alertes.csv sauvegarde.")
    return data


def demo(nw):
    import random
    print("[*] Mode demo.")

    for port in range(1, 220):
        nw.ports_vus["192.168.1.50"].add(port)
        nw.tentatives["192.168.1.50"][port] += 1
        nw.trafic["192.168.1.50"] += 60

    nw.compteur_syn["172.16.0.200"] = 180
    nw.nb_pings["172.16.0.200"] = 70
    nw.trafic["172.16.0.200"] = 12000

    nw.tentatives["10.0.0.77"][22] = 80
    nw.tentatives["10.0.0.77"][3389] = 25
    nw.ports_vus["10.0.0.77"].add(22)
    nw.ports_vus["10.0.0.77"].add(3389)
    nw.trafic["10.0.0.77"] = 18000

    for i in range(5):
        nw.table_arp["192.168.1.1"].add(f"aa:bb:cc:dd:ee:{i:02x}")

    for i in range(40):
        nw.requetes_dns["10.0.0.55"].append(f"cmd{i}.malware.xyz.")
    nw.trafic["10.0.0.55"] = 4000

    nw.trafic["192.168.1.101"] = random.randint(5000, 40000)
    nw.trafic["192.168.1.102"] = random.randint(5000, 40000)

    nw.protos.update({"TCP": 4200, "UDP": 800, "ICMP": 70, "DNS": 40})
    nw.infos = {
        "fichier": "demo.pcap",
        "debut": "2024-03-15 10:00:00",
        "fin": "2024-03-15 10:12:43",
        "duree_secondes": 763,
        "total_paquets": 5110,
        "total_ips": len(nw.trafic),
        "protocoles": dict(nw.protos),
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NetWatch - analyse de fichiers PCAP")
    parser.add_argument("-f", "--fichier", help="fichier .pcap a analyser")
    parser.add_argument("--demo", action="store_true", help="mode demo sans fichier")
    args = parser.parse_args()

    if not args.fichier and not args.demo:
        print("Usage :")
        print("  python netwatch.py -f capture.pcap")
        print("  python netwatch.py --demo")
        exit()

    nw = NetWatch(args.fichier or "demo.pcap")

    if args.demo or not args.fichier:
        demo(nw)
    else:
        if not nw.charger():
            exit()
        nw.analyser()

    nw.detecter()
    nw.afficher()
    nw.sauvegarder()
    print("[ok] Lance : python dashboard.py")
