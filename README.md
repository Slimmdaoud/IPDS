# IDPS Sentinel - Système Hybride de Détection d'Intrusions

IDPS Sentinel est un système de détection et de prévention d'intrusions (IDPS) combinant des **règles statiques** et de l'**Intelligence Artificielle**.

## 🚀 Fonctionnalités
- **Analyse en temps réel** : Capture de paquets via Scapy.
- **Détection Hybride** : 
  - Règles (SYN Flood, Port Scan, UDP Flood).
  - Machine Learning (Modèle Random Forest entraîné sur le dataset NSL-KDD).
- **Prévention Active** : Blocage automatique des IPs via IPTables.
- **Dashboard Web** : Interface Flask pour visualiser le trafic et les alertes.

## 🛠️ Installation
1. Cloner le projet : `git clone <votre-url-github>`
2. Installer les dépendances : `pip install -r requirements.txt`
3. Entraîner l'IA : Placez `KDDTrain+.txt` dans le dossier et lancez `python3 train_ai.py`
4. Lancer l'IDPS : `sudo python3 gui_flask.py`

## 📊 Dataset
Le modèle IA utilise le dataset **NSL-KDD** (Kaggle) pour identifier les anomalies réseau avec un score de confiance.
