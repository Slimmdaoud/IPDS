import threading
import subprocess
from pathlib import Path

# Nom du fichier où sont stockées les IPs bannies
BLACKLIST_FILE = "blacklist.txt"

class BlacklistManager:
    def __init__(self):
        """Initialise le gestionnaire de liste noire."""
        self._lock = threading.Lock()
        self._blacklist = set()
        self._load_from_file()

    def _load_from_file(self):
        """Charge les IPs bannies depuis le fichier texte au démarrage."""
        path = Path(BLACKLIST_FILE)
        if path.exists():
            with path.open("r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self._blacklist.add(ip)
            print(f"[SYSTEM] {len(self._blacklist)} IPs chargées depuis la blacklist.")

    def _save_to_file(self):
        """Sauvegarde la liste actuelle dans le fichier texte."""
        path = Path(BLACKLIST_FILE)
        with path.open("w") as f:
            for ip in sorted(self._blacklist):
                f.write(ip + "\n")

    def _iptables_block_ip(self, ip):
        """
        Ajoute une règle iptables pour bloquer tout trafic entrant d'une IP.
        Nécessite les droits ROOT.
        """
        try:
            # -A INPUT : Ajoute à la fin de la chaîne d'entrée
            # -s : source IP
            # -j DROP : rejette le paquet sans réponse
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[IPTABLES] BLOCK : Règle ajoutée pour {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[IPTABLES] Erreur lors du blocage de {ip}: {e.stderr.decode().strip()}")

    def _iptables_unblock_ip(self, ip):
        """
        Supprime la règle iptables DROP pour une IP spécifique.
        Nécessite les droits ROOT.
        """
        try:
            # -D INPUT : Supprime la règle correspondant exactement aux paramètres
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[IPTABLES] UNBLOCK : Règle supprimée pour {ip}")
        except subprocess.CalledProcessError as e:
            # L'erreur arrive souvent si la règle n'existait plus
            print(f"[IPTABLES] Erreur lors du déblocage de {ip}: {e.stderr.decode().strip()}")

    def add_ip(self, ip):
        """Ajoute une IP à la blacklist et applique le blocage système."""
        if not ip: return
        
        with self._lock:
            if ip not in self._blacklist:
                self._blacklist.add(ip)
                self._save_to_file()
                self._iptables_block_ip(ip)
                return True
        return False

    def remove_ip(self, ip):
        """Supprime une IP de la blacklist et lève le blocage système."""
        if not ip: return False

        with self._lock:
            if ip in self._blacklist:
                self._blacklist.remove(ip)
                self._save_to_file()
                self._iptables_unblock_ip(ip)
                return True
        return False

    def is_blocked(self, ip):
        """Vérifie si une IP est actuellement dans la liste noire."""
        with self._lock:
            return ip in self._blacklist

    def get_all(self):
        """Retourne la liste de toutes les IPs bannies."""
        with self._lock:
            return list(self._blacklist)

# --- Test rapide (si exécuté seul) ---
if __name__ == "__main__":
    bm = BlacklistManager()
    # Test ajout
    test_ip = "192.168.1.50"
    print(f"Test de blocage sur {test_ip}...")
    bm.add_ip(test_ip)
    
    # Test lecture
    print(f"Liste actuelle : {bm.get_all()}")
    
    # Test suppression
    # bm.remove_ip(test_ip)
