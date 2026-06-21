"""
trainer.py — train both sklearn models from CSV and save with joblib.
Run:  python trainer.py
"""
import pandas as pd
from models.anomaly_model import AnomalyModel
from models.attack_classifier import AttackClassifier

TRAINING_DATA_CSV     = "data/training_data.csv"
ANOMALY_MODEL_PATH    = "models/anomaly_model.pkl"
CLASSIFIER_MODEL_PATH = "models/attack_classifier.pkl"

NUMERIC_FEATURES = ["packet_size", "is_tcp", "is_udp", "src_port", "dst_port"]

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["is_tcp"] = (df["protocol"] == "TCP").astype(int)
    df["is_udp"] = (df["protocol"] == "UDP").astype(int)
    return df[NUMERIC_FEATURES]

def train():
    df = pd.read_csv(TRAINING_DATA_CSV)
    X  = build_features(df)
    y  = df["label"] if "label" in df.columns else ["NORMAL"] * len(df)

    anomaly = AnomalyModel()
    anomaly.train(X)
    anomaly.save(ANOMALY_MODEL_PATH)
    print(f"[INFO] Anomaly model saved -> {ANOMALY_MODEL_PATH}")

    classifier = AttackClassifier()
    classifier.train(X, y)
    classifier.save(CLASSIFIER_MODEL_PATH)
    print(f"[INFO] Classifier saved    -> {CLASSIFIER_MODEL_PATH}")
    print("[INFO] Training complete.")

if __name__ == "__main__":
    train()
