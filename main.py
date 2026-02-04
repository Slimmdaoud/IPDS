import time
from sniffing import start_sniff
from detection import DetectionEngine
from logger import log_alert
from prevention import BlacklistManager
from ml_model import MLDetector
from collections import deque

# ==========================================
# CONFIGURATION DU SYSTÈME
# ==========================================
IFACE = "ens33"             # Votre interface réseau (ex: ens33, eth0, wlan0)
BPF_FILTER = "tcp or udp"   # Filtre de capture (uniquement trafic utile)
WHITELIST = ["127.0.0.1","192.168.146.131","192.168.146.1","192.168.146.254"]

# ==========================================
# INITIALISATION DES MODULES
# ==========================================
detector = DetectionEngine()
blacklist = BlacklistManager()
ia_detector = MLDetector()
packet_counter = 0

# Files d'attente pour le Dashboard Flask
RECENT_PACKETS = deque(maxlen=100)
ALERTS = deque(maxlen=100)

def handle_packet(pkt, feats):
    """
    Fonction principale de traitement appelée pour chaque paquet capturé.
    """
    global packet_counter
    packet_counter += 1

    src_ip = feats.get("src_ip")
    dst_ip = feats.get("dst_ip")

    # 1. Ignorer si pas d'IP source ou si l'IP est déjà bloquée
    if not src_ip or blacklist.is_blocked(src_ip):
        return

    # 2. Préparation des données pour l'affichage JSON (GUI)
    # Correction de l'erreur 'FlagValue is not JSON serializable'
    display_feats = feats.copy()
    if display_feats.get("tcp_flags") is not None:
        display_feats["tcp_flags"] = str(display_feats["tcp_flags"])
    
    RECENT_PACKETS.append(display_feats)

    # -------------------------------------------------------
    # 3. DÉTECTION PAR INTELLIGENCE ARTIFICIELLE (Random Forest)
    # -------------------------------------------------------
    is_attack, confidence = ia_detector.predict(feats["protocol"], feats["length"])
    
    if is_attack == 1 and src_ip not in WHITELIST:
        details = f"Score IA: {confidence:.2f}% (Dataset NSL-KDD)"
        a_type = "IA_ANOMALY"
        
        print(f"[IA ALERT] {src_ip} -> {dst_ip} | Confiance: {confidence:.2f}%")
        
        # Enregistrer l'alerte
        alert_data = {
            "type": a_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "details": details,
            "source": "Machine Learning"
        }
        ALERTS.append(alert_data)
        log_alert(a_type, src_ip, dst_ip, details)
        
        # Bloquer l'IP via IPTables
        blacklist.add_ip(src_ip)
        print(f"[PREVENTION] {src_ip} banni par l'IA.")
        return # Si l'IA a détecté l'attaque, on arrête le traitement pour ce paquet

    # -------------------------------------------------------
    # 4. DÉTECTION PAR RÈGLES CLASSIQUES (Signature / Seuils)
    # -------------------------------------------------------
    alert = detector.detect(feats)
    if alert and alert["src_ip"] not in WHITELIST:
        s_ip = alert["src_ip"]
        d_ip = alert["dst_ip"]
        
        # Ajouter l'information de source pour le GUI
        alert["source"] = "Règles Statiques"
        
        print(f"[RULE ALERT] {alert['type']} détecté de {s_ip}")
        
        # Enregistrer l'alerte
        ALERTS.append(alert)
        log_alert(alert["type"], s_ip, d_ip, alert["details"])
        
        # Bloquer l'IP
        blacklist.add_ip(s_ip)
        print(f"[PREVENTION] {s_ip} banni par règle de sécurité.")

# ==========================================
# POINT D'ENTRÉE DU PROGRAMME
# ==========================================
if __name__ == "__main__":
    print("==================================================")
    print("       IDPS SENTINEL - HYBRID AI SYSTEM           ")
    print("==================================================")
    print(f"[*] Interface : {IFACE}")
    print(f"[*] Filtre    : {BPF_FILTER}")
    
    if ia_detector.model:
        print("[*] Moteur IA : CHARGÉ (Prêt)")
    else:
        print("[!] Moteur IA : ERREUR (Fichiers manquants)")

    print("[*] Sniffing en cours... (Ctrl+C pour arrêter)")
    
    try:
        # Lancement de la capture réseau via Scapy
        start_sniff(IFACE, handle_packet, BPF_FILTER)
    except KeyboardInterrupt:
        print("\n[!] Arrêt manuel demandé par l'utilisateur.")
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}")
