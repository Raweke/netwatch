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
    print("[!] Mode demonstration active.\n")

SEUILS = {
    "scan_ports"  : 15,
    "syn_flood"   : 100,
    "brute_force" : 10,
    "icmp_flood"  : 50,
    "dns_suspect" : 30,
}

PORTS_SENSIBLES = {
    22: "SSH", 23: "Telnet", 21: "FTP",
    3389: "RDP", 445: "SMB", 3306: "MySQL",
    6379: "Redis", 5900: "VNC", 80: "HTTP", 443: "HTTPS"
}


class NetWatch:

    def __init__(self, fichier_pcap: str):
        self.fichier       = fichier_pcap
        self.paquets       = []
        self.alertes       = []
        self.ports_par_ip  = defaultdict(set)
        self.syn_par_ip    = defaultdict(int)
        self.tentatives    = defaultdict(Counter)
        self.table_arp     = defaultdict(set)
        self.pings_par_ip  = defaultdict(int)
        self.dns_par_ip    = defaultdict(list)
        self.volume_par_ip = defaultdict(int)
        self.protocoles    = Counter()
        self.infos         = {}

    def charger(self) -> bool:
        if not SCAPY_OK:
            return False
        chemin = Path(self.fichier)
        if not chemin.exists():
            print(f"[!] Fichier introuvable : {self.fichier}")
            return False
        print(f"[*] Lecture de {chemin.name}...")
        try:
            self.paquets = rdpcap(str(chemin))
            print(f"[+] {len(self.paquets)} paquets charges.")
            return True
        except Exception as e:
            print(f"[!] Erreur : {e}")
            return False

    def analyser(self):
        print("[*] Analyse en cours...")
        if not self.paquets:
            print("[!] Aucun paquet a analyser.")
            return

        debut = float(self.paquets[0].time)
        fin   = float(self.paquets[-1].time)

        for paquet in self.paquets:
            if not paquet.haslayer(IP):
                continue

            src  = paquet[IP].src
            size = len(paquet)
            self.volume_par_ip[src] += size

            if paquet.haslayer(TCP):
                port_dest = paquet[TCP].dport
                flags     = paquet[TCP].flags
                self.protocoles["TCP"] += 1
                self.ports_par_ip[src].add(port_dest)
                self.tentatives[src][port_dest] += 1
                if flags == 0x02:
                    self.syn_par_ip[src] += 1

            elif paquet.haslayer(UDP):
                self.protocoles["UDP"] += 1
                self.ports_par_ip[src].add(paquet[UDP].dport)
                if paquet.haslayer(DNS) and paquet[DNS].qr == 0:
                    self.protocoles["DNS"] += 1
                    try:
                        domaine = paquet[DNS].qd.qname.decode()
                        self.dns_par_ip[src].append(domaine)
                    except Exception:
                        pass

            elif paquet.haslayer(ICMP):
                self.protocoles["ICMP"] += 1
                self.pings_par_ip[src] += 1

            if paquet.haslayer(ARP):
                self.protocoles["ARP"] += 1
                arp = paquet[ARP]
                if arp.op == 2:
                    self.table_arp[arp.psrc].add(arp.hwsrc)

        self.infos = {
            "fichier"        : self.fichier,
            "debut"          : datetime.fromtimestamp(debut).strftime("%Y-%m-%d %H:%M:%S"),
            "fin"            : datetime.fromtimestamp(fin).strftime("%Y-%m-%d %H:%M:%S"),
            "duree_secondes" : round(fin - debut, 2),
            "total_paquets"  : len(self.paquets),
            "total_ips"      : len(self.volume_par_ip),
            "protocoles"     : dict(self.protocoles),
        }
        print("[+] Analyse terminee.")

    def detecter(self):
        print("[*] Detection des menaces...")

        for ip, ports in self.ports_par_ip.items():
            if len(ports) >= SEUILS["scan_ports"]:
                severite = "CRITIQUE" if len(ports) > 50 else "ELEVE"
                self._alerte(severite, "Scan de ports", ip,
                    f"Scan de {len(ports)} ports distincts detecte")

        for ip, nb in self.syn_par_ip.items():
            if nb >= SEUILS["syn_flood"]:
                self._alerte("CRITIQUE", "SYN Flood", ip,
                    f"{nb} paquets SYN envoyes sans completer la connexion")

        for ip, compteur in self.tentatives.items():
            for port, nb in compteur.items():
                if port in PORTS_SENSIBLES and nb >= SEUILS["brute_force"]:
                    self._alerte("ELEVE", "Brute Force", ip,
                        f"{nb} tentatives sur le port {port} ({PORTS_SENSIBLES[port]})")

        for ip, macs in self.table_arp.items():
            if len(macs) >= 3:
                self._alerte("ELEVE", "ARP Spoofing", ip,
                    f"L'IP {ip} repond avec {len(macs)} adresses MAC differentes")

        for ip, nb in self.pings_par_ip.items():
            if nb >= SEUILS["icmp_flood"]:
                self._alerte("MOYEN", "ICMP Flood", ip,
                    f"{nb} paquets ICMP envoyes")

        for ip, domaines in self.dns_par_ip.items():
            if len(domaines) >= SEUILS["dns_suspect"]:
                self._alerte("MOYEN", "DNS Suspect", ip,
                    f"{len(domaines)} requetes DNS vers {len(set(domaines))} domaines")

        print(f"[+] {len(self.alertes)} alerte(s) detectee(s).")

    def _alerte(self, severite, type_attaque, ip, description):
        self.alertes.append({
            "id"          : len(self.alertes) + 1,
            "severite"    : severite,
            "type"        : type_attaque,
            "ip"          : ip,
            "description" : description,
            "heure"       : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    def score_risque(self):
        points = sum({"CRITIQUE": 30, "ELEVE": 15, "MOYEN": 5}.get(a["severite"], 0)
                     for a in self.alertes)
        score  = min(100, points)
        niveau = ("CRITIQUE" if score >= 75 else "ELEVE" if score >= 50
                  else "MOYEN" if score >= 25 else "FAIBLE")
        return score, niveau

    def top_ips(self, n=8):
        trie = sorted(self.volume_par_ip.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "ko": round(b / 1024, 1)} for ip, b in trie[:n]]

    def afficher(self):
        score, niveau = self.score_risque()
        print("\n" + "-" * 50)
        print("  NETWATCH - RESUME")
        print("-" * 50)
        print(f"  Fichier  : {self.fichier}")
        print(f"  Paquets  : {self.infos.get('total_paquets', 0)}")
        print(f"  IPs      : {self.infos.get('total_ips', 0)}")
        print(f"  Duree    : {self.infos.get('duree_secondes', 0)}s")
        print(f"  Risque   : {score}/100 - {niveau}")
        print(f"  Alertes  : {len(self.alertes)}")
        for a in self.alertes:
            print(f"    [{a['severite']:<8}] {a['type']:<15} {a['ip']}")
        print("-" * 50)

    def exporter_json(self, chemin="rapport.json"):
        score, niveau = self.score_risque()
        rapport = {
            "infos"     : self.infos,
            "score"     : score,
            "niveau"    : niveau,
            "alertes"   : self.alertes,
            "top_ips"   : self.top_ips(),
            "genere_le" : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        with open(chemin, "w", encoding="utf-8") as f:
            json.dump(rapport, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON sauvegarde : {chemin}")
        return rapport

    def exporter_csv(self, chemin="alertes.csv"):
        if not self.alertes:
            return
        with open(chemin, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["id","severite","type","ip","description","heure"])
            writer.writeheader()
            writer.writerows(self.alertes)
        print(f"[+] CSV sauvegarde : {chemin}")


def charger_demo(nw: NetWatch):
    import random
    print("[*] Mode DEMO - donnees simulees.")

    for port in range(1, 220):
        nw.ports_par_ip["192.168.1.50"].add(port)
        nw.tentatives["192.168.1.50"][port] += 1
        nw.volume_par_ip["192.168.1.50"] += 60

    nw.syn_par_ip["172.16.0.200"] = 180
    nw.pings_par_ip["172.16.0.200"] = 70
    nw.volume_par_ip["172.16.0.200"] = 12000

    nw.tentatives["10.0.0.77"][22] = 80
    nw.tentatives["10.0.0.77"][3389] = 25
    nw.ports_par_ip["10.0.0.77"].add(22)
    nw.ports_par_ip["10.0.0.77"].add(3389)
    nw.volume_par_ip["10.0.0.77"] = 18000

    for i in range(5):
        nw.table_arp["192.168.1.1"].add(f"aa:bb:cc:dd:ee:{i:02x}")

    for i in range(40):
        nw.dns_par_ip["10.0.0.55"].append(f"cmd{i}.malware.xyz.")
    nw.volume_par_ip["10.0.0.55"] = 4000

    for ip in ["192.168.1.101", "192.168.1.102"]:
        nw.ports_par_ip[ip].add(80)
        nw.ports_par_ip[ip].add(443)
        nw.volume_par_ip[ip] = random.randint(5000, 40000)

    nw.protocoles.update({"TCP": 4200, "UDP": 800, "ICMP": 70, "DNS": 40})
    nw.infos = {
        "fichier"         : "demo.pcap",
        "debut"           : "2024-03-15 10:00:00",
        "fin"             : "2024-03-15 10:12:43",
        "duree_secondes"  : 763,
        "total_paquets"   : 5110,
        "total_ips"       : len(nw.volume_par_ip),
        "protocoles"      : dict(nw.protocoles),
    }
    print("[+] Donnees demo chargees.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NetWatch - Analyseur PCAP")
    parser.add_argument("-f", "--fichier", help="Fichier PCAP a analyser")
    parser.add_argument("--demo", action="store_true", help="Mode demonstration")
    args = parser.parse_args()

    if not args.fichier and not args.demo:
        print("Usage :")
        print("  python netwatch.py --demo")
        print("  python netwatch.py -f capture.pcap")
        exit()

    nw = NetWatch(args.fichier or "demo.pcap")

    if args.demo or not args.fichier:
        charger_demo(nw)
    else:
        if not nw.charger():
            exit()
        nw.analyser()

    nw.detecter()
    nw.afficher()
    nw.exporter_json("rapport.json")
    nw.exporter_csv("alertes.csv")
    print("\n[ok] Lance maintenant : python dashboard.py")
