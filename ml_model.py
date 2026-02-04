import joblib
import numpy as np
import os

class MLDetector:
    def __init__(self):
        # Chemins vers les fichiers générés par train_ai.py
        self.model_path = "ids_model.pkl"
        self.scaler_path = "scaler.pkl"
        
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            print("[IA] Modèle et Scaler chargés avec succès.")
        else:
            self.model = None
            self.scaler = None
            print("[!] Attention : Fichiers ids_model.pkl ou scaler.pkl introuvables.")

    def predict(self, protocol, length):
        """
        Prédit si un paquet est une attaque et retourne le score de confiance.
        Retourne : (prediction, confidence_score)
        """
        if self.model is None or self.scaler is None:
            return 0, 0.0

        proto_num = 6 if protocol == "TCP" else 17 if protocol == "UDP" else 1

        features = np.array([[proto_num, length, 1]])

        try:
            features_scaled = self.scaler.transform(features)

            prediction = self.model.predict(features_scaled)[0]

            probabilities = self.model.predict_proba(features_scaled)[0]
            confidence = probabilities[prediction] * 100  # Conversion en pourcentage
            print(f"[DEBUG IA] {protocol} len:{length} -> Pred:{prediction} ({confidence:.2f}%)")

            return int(prediction), float(confidence)
        except Exception as e:
            print(f"[IA ERROR] Erreur lors de la prédiction : {e}")
            return 0, 0.0
