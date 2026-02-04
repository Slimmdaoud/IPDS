from flask import Flask, render_template, jsonify
import threading
import main

app = Flask(__name__)

@app.route("/")
def index():
    # Retourne simplement la page HTML vide
    return render_template("index.html")

@app.route("/api/data")
def get_data():
    """Endpoint pour envoyer les données au format JSON au frontend."""
    return jsonify({
        "stats": {
            "total_packets": main.packet_counter
        },
        "alerts": list(main.ALERTS),
        "packets": list(main.RECENT_PACKETS),
        "blacklist": main.blacklist.get_all()
    })

@app.route("/api/unblock/<ip>", methods=["POST"])
def unblock_ip(ip):
    success = main.blacklist.remove_ip(ip)
    if success:
        return jsonify({"status": "success", "message": f"IP {ip} débloquée"}), 200
    else:
        return jsonify({"status": "error", "message": "IP non trouvée"}), 404
def start_sniffer_thread():
    t = threading.Thread(
        target=main.start_sniff,
        args=(main.IFACE, main.handle_packet, main.BPF_FILTER),
        daemon=True
    )
    t.start()

if __name__ == "__main__":
    print("[*] Démarrage du sniffer...")
    start_sniffer_thread()
    # Debug=False est important quand on utilise des threads Scapy
    app.run(host="0.0.0.0", port=5000, debug=False)
