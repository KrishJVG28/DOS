import math
from collections import Counter
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class HybridDetectionEngine:
    def __init__(self, entropy_threshold):
        self.entropy_threshold = entropy_threshold
        self.clf = RandomForestClassifier(n_estimators=10, random_state=42)
        self._train_smarter_model()

    def _train_smarter_model(self):
        X = np.array([
            [100, 2.0], [250, 2.5], [500, 1.5],     # Normal everyday traffic
            [5000, 5.0], [6500, 6.0], [8000, 4.5],  # Flash Crowd (High volume, diverse IPs = High Entropy)
            [10000, 1.0], [15000, 0.5], [20000, 0.1] # DoS Attack (High volume, spoofed/repetitive IPs = Low Entropy)
        ])
        
        # Labels: 0 = NORMAL, 1 = FLASH_CROWD, 2 = DOS_ATTACK
        y = np.array([0, 0, 0, 1, 1, 1, 2, 2, 2])
        self.clf.fit(X, y)

    def calculate_entropy(self, ip_list):
        if not ip_list: return 0.0
        counts = Counter(ip_list)
        total = len(ip_list)
        return -sum((c/total) * math.log2(c/total) for c in counts.values())

    def analyze_traffic(self, packet_count, source_ips):
        entropy = self.calculate_entropy(source_ips)
        
        # Feed the data to our now properly-educated Random Forest AI
        features = np.array([[packet_count, entropy]])
        prediction = self.clf.predict(features)[0]
        
        labels = {0: "NORMAL", 1: "FLASH_CROWD", 2: "DOS_ATTACK"}
        return labels[prediction], entropy