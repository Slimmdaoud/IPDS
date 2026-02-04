import time
from collections import defaultdict

TIME_WINDOW = 10

SYN_FLOOD_THRESHOLD = 10
PORT_SCAN_THRESHOLD = 30
UDP_FLOOD_THRESHOLD = 100
ARP_SPOOF_DUP_MAC_THRESHOLD = 2

class DetectionEngine:
    def __init__(self):
        self.syn_history = defaultdict(list)
        self.port_scan_history = defaultdict(set)
        self.udp_history = defaultdict(list)
        self.arp_table = defaultdict(set)
        self.last_alert_time = {}
        self.alert_cooldown = 10

    def _can_alert(self, alert_key):
        now = time.time()
        last = self.last_alert_time.get(alert_key, 0)
        if now - last > self.alert_cooldown:
            self.last_alert_time[alert_key] = now
            return True
        return False

    def _cleanup_old_entries(self, history_dict):
        now = time.time()
        for key, ts_list in list(history_dict.items()):
            history_dict[key] = [t for t in ts_list if now - t <= TIME_WINDOW]
            if not history_dict[key]:
                del history_dict[key]

    def detect(self, feats):
        src_ip = feats.get("src_ip")
        dst_ip = feats.get("dst_ip")
        proto = feats.get("protocol")
        flags = feats.get("tcp_flags")
        src_port = feats.get("src_port")
        dst_port = feats.get("dst_port")
        arp_op = feats.get("arp_op")

        now = time.time()

        # --- Détection SYN flood (TCP SYN sans ACK) ---
        # Flags SYN: bit 2 (valeur 0x02)
        if proto == "TCP" and flags is not None and (flags & 0x02):
            self.syn_history[src_ip].append(now)
            # nettoyage
            self._cleanup_old_entries(self.syn_history)

            count_syn = len(self.syn_history.get(src_ip, []))
            if count_syn > SYN_FLOOD_THRESHOLD:
                alert_key = ("SYN_FLOOD", src_ip)
                if self._can_alert(alert_key):
                    return {
                        "type": "SYN_FLOOD",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "details": f"{count_syn} SYN packets in {TIME_WINDOW}s"
                    }

        # --- Détection scan de ports (beaucoup de ports différents touchés) ---
        if proto == "TCP" and dst_port is not None:
            key = (src_ip, dst_ip)
            self.port_scan_history[key].add(dst_port)

            port_count = len(self.port_scan_history[key])
            if port_count > PORT_SCAN_THRESHOLD:
                alert_key = ("PORT_SCAN", src_ip, dst_ip)
                if self._can_alert(alert_key):
                    return {
                        "type": "PORT_SCAN",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "details": f"{port_count} different TCP ports scanned"
                    }

        # --- Détection UDP flood ---
        if proto == "UDP":
            self.udp_history[src_ip].append(now)
            self._cleanup_old_entries(self.udp_history)

            count_udp = len(self.udp_history.get(src_ip, []))
            if count_udp > UDP_FLOOD_THRESHOLD:
                alert_key = ("UDP_FLOOD", src_ip)
                if self._can_alert(alert_key):
                    return {
                        "type": "UDP_FLOOD",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "details": f"{count_udp} UDP packets in {TIME_WINDOW}s"
                    }

        # --- Détection ARP spoofing (IP vue avec plusieurs MAC) ---
        # Ici, on suppose que tu complèteras plus tard avec la MAC
        # dans extract_features (sniffing.py) si besoin.
        # Exemple simple: une même IP associée à plusieurs MAC.
        if proto == "ARP" and arp_op is not None:
            # TODO: ajouter les MAC src/dst dans feats pour une vraie détection.
            # On laisse un placeholder.
            pass

        return None
