"""
ml_service.py — TCP server that receives feature JSON from the C++ backend,
runs both sklearn models, and returns a prediction JSON.

Protocol (newline-delimited JSON, one request per connection):
  Request:   {"packet_size":512,"is_tcp":1,"is_udp":0,"src_port":1234,"dst_port":80,"src_ip":"...","dst_ip":"..."}\n
  Response:  {"status":"THREAT","attack_type":"DDoS"}\n
             {"status":"NORMAL","attack_type":""}\n

Run:  python ml_service.py
      (keep running while the C++ binary is active)
"""

import json
import logging
import os
import socketserver
import threading

import numpy as np

from models.anomaly_model import AnomalyModel
from models.attack_classifier import AttackClassifier

# ── Config ────────────────────────────────────────────────────────────────────
HOST                  = "127.0.0.1"
PORT                  = 9999
ANOMALY_MODEL_PATH    = "models/anomaly_model.pkl"
CLASSIFIER_MODEL_PATH = "models/attack_classifier.pkl"
NUMERIC_FEATURES      = ["packet_size", "is_tcp", "is_udp", "src_port", "dst_port"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("ml_service.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ── Load models once at startup ───────────────────────────────────────────────
anomaly_model = AnomalyModel()
classifier    = AttackClassifier()

if os.path.exists(ANOMALY_MODEL_PATH):
    anomaly_model.load(ANOMALY_MODEL_PATH)
    log.info(f"Anomaly model loaded from {ANOMALY_MODEL_PATH}")
else:
    log.warning("Anomaly model not found — train first with trainer.py")

if os.path.exists(CLASSIFIER_MODEL_PATH):
    classifier.load(CLASSIFIER_MODEL_PATH)
    log.info(f"Classifier loaded from {CLASSIFIER_MODEL_PATH}")
else:
    log.warning("Classifier not found — train first with trainer.py")


# ── Request handler ───────────────────────────────────────────────────────────
class MLHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw = self.rfile.readline().decode("utf-8").strip()
            if not raw:
                return
            data = json.loads(raw)

            # Build numpy feature vector in expected order
            vec = np.array([[
                data.get("packet_size", 0),
                data.get("is_tcp",      0),
                data.get("is_udp",      0),
                data.get("src_port",    0),
                data.get("dst_port",    0),
            ]], dtype=float)

            anomaly = anomaly_model.predict(vec)   # -1 = anomaly, 1 = normal

            if anomaly == -1:
                attack_type = str(classifier.predict(vec))
                result = {"status": "THREAT", "attack_type": attack_type}
                log.info(f"THREAT: {attack_type} from {data.get('src_ip', '?')}")
            else:
                result = {"status": "NORMAL", "attack_type": ""}

            response = (json.dumps(result) + "\n").encode("utf-8")
            self.wfile.write(response)

        except json.JSONDecodeError as e:
            log.error(f"JSON parse error: {e}")
            self.wfile.write(b'{"status":"NORMAL","attack_type":""}\n')
        except Exception as e:
            log.error(f"Handler error: {e}")
            self.wfile.write(b'{"status":"NORMAL","attack_type":""}\n')


# ── Threaded TCP server ───────────────────────────────────────────────────────
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def main():
    with ThreadedTCPServer((HOST, PORT), MLHandler) as server:
        log.info(f"ML service listening on {HOST}:{PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log.info("ML service stopped.")


if __name__ == "__main__":
    main()
