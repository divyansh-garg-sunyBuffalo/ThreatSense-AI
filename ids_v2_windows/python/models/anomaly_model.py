from sklearn.ensemble import IsolationForest
import joblib

class AnomalyModel:

    def __init__(self):
        self.model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)

    def train(self, dataset):
        self.model.fit(dataset)

    def predict(self, features):
        return self.model.predict(features)[0]  # -1 = anomaly, 1 = normal

    def save(self, path):
        joblib.dump(self.model, path)

    def load(self, path):
        self.model = joblib.load(path)
