from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, DNSQR

def extract_features(pkt):
    """Retourne un dict contenant les infos importantes d'un paquet."""
    features = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "tcp_flags": None,
        "arp_op": None,
        "dns_qname": None,
        "length": len(pkt) # Important pour l'IA
    }

    if IP in pkt:
        features["src_ip"] = pkt[IP].src
        features["dst_ip"] = pkt[IP].dst
        proto = pkt[IP].proto
        if proto == 6:
            features["protocol"] = "TCP"
        elif proto == 17:
            features["protocol"] = "UDP"
        else:
            features["protocol"] = str(proto)

    if TCP in pkt:
        features["src_port"] = pkt[TCP].sport
        features["dst_port"] = pkt[TCP].dport
        # CORRECTION JSON : On convertit l'objet FlagValue en entier
        features["tcp_flags"] = int(pkt[TCP].flags) 

    if UDP in pkt:
        features["src_port"] = pkt[UDP].sport
        features["dst_port"] = pkt[UDP].dport

    if ARP in pkt:
        features["protocol"] = "ARP"
        features["arp_op"] = pkt[ARP].op

    if DNS in pkt and pkt.haslayer(DNSQR):
        features["protocol"] = "DNS"
        features["dns_qname"] = pkt[DNSQR].qname.decode(errors="ignore")

    return features

def start_sniff(iface, packet_callback, bpf_filter=None):
    """Lance la capture Scapy."""
    def _scapy_callback(pkt):
        feats = extract_features(pkt)
        packet_callback(pkt, feats)

    sniff(
        iface=iface,
        prn=_scapy_callback,
        store=False,
        filter=bpf_filter
    )
