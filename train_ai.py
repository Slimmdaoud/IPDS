import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

def train_idps_ia(file_path):
    # Colonnes simplifiées pour correspondre à ce qu'on peut sniffer en temps réel
    # On choisit des index précis du dataset NSL-KDD
    # Index 1: Protocol, Index 4: Src_bytes, Index 22: Count
    cols = [1, 4, 22] 
    
    # Charger le dataset sans header
    df = pd.read_csv(file_path, header=None)
    
    # X = Features, y = Label (colonne 41 dans NSL-KDD)
    X = df[cols]
    y = df[41].apply(lambda x: 0 if x == 'normal' else 1)

    # Convertir le protocole (tcp, udp, icmp) en nombres
    X[1] = X[1].map({'tcp': 6, 'udp': 17, 'icmp': 1}).fillna(0)

    # Scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Modèle
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_scaled, y)

    # Sauvegarde
    joblib.dump(model, "ids_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    print("[OK] Modèle IA entraîné et sauvegardé !")

if __name__ == "__main__":
    # Assure-toi que le fichier KDDTrain+.txt est dans le même dossier
    train_idps_ia("KDDTrain+.txt")
