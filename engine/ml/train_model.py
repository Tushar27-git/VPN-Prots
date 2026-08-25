"""
Model Training & Calibration Pipeline for Encrypted ESP Traffic Classification.
Generates empirical flow training distributions, extracts statistical features,
trains a CalibratedClassifierCV Random Forest ensemble, evaluates metrics,
and saves the deployable model artifact.
"""

import os
import random
import joblib
import numpy as np
from typing import Dict, List, Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix

from testbed.traffic_generators import TrafficGenerator
from engine.ml.feature_extractor import ESPFlowFeatureExtractor


def generate_training_dataset(samples_per_class: int = 120) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Synthesizes training dataset spanning all 6 traffic categories with varied
    duration, network jitter, packet burstiness, and packet size distributions.
    """
    tg = TrafficGenerator()
    extractor = ESPFlowFeatureExtractor()

    X_list = []
    y_list = []

    for cat in tg.CATEGORIES:
        for i in range(samples_per_class):
            # Vary duration and network conditions
            duration = random.uniform(3.0, 12.0)
            flow_pkts = tg.generate_flow_by_type(cat, duration_sec=duration)

            # Convert to packet records
            esp_records = []
            for j, p in enumerate(flow_pkts):
                src = "10.10.0.2" if p["direction"] == 1 else "10.10.0.3"
                dst = "10.10.0.3" if p["direction"] == 1 else "10.10.0.2"
                esp_records.append({
                    "time": p["timestamp"],
                    "src_ip": src,
                    "dst_ip": dst,
                    "length": p["size"],
                    "spi": "0xC01A2026",
                    "seq": j + 1
                })

            res = extractor.extract_features_from_packets(esp_records, initiator_ip="10.10.0.2")
            if res.get("vector") and len(res["vector"]) == len(extractor.FEATURE_NAMES):
                X_list.append(res["vector"])
                y_list.append(cat)

    return np.array(X_list), np.array(y_list), extractor.FEATURE_NAMES


def train_and_save_model(output_path: str = "engine/ml/model_artifacts/ipsec_traffic_classifier.joblib") -> Dict[str, Any]:
    """
    Trains, calibrates, validates, and serializes the ESP traffic model.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print("Generating statistical flow dataset for training...")
    X, y, feature_names = generate_training_dataset(samples_per_class=150)
    print(f"Dataset generated: {X.shape[0]} samples, {X.shape[1]} features.")

    # 1. Feature Scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 2. Base Estimator: Random Forest with balanced class weights
    base_rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42
    )

    # 3. Calibrated Classifier (Sigmoid / Platt scaling via 5-fold CV)
    calibrated_model = CalibratedClassifierCV(
        estimator=base_rf,
        method="sigmoid",
        cv=5
    )
    calibrated_model.fit(X_scaled, y)

    # 4. Cross validation evaluation
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(calibrated_model, X_scaled, y, cv=skf, scoring="accuracy")
    mean_acc = float(np.mean(scores))
    print(f"5-Fold Calibrated CV Accuracy: {mean_acc*100:.2f}% (+/- {float(np.std(scores))*100:.2f}%)")

    # 5. Save Artifact
    bundle = {
        "model": calibrated_model,
        "scaler": scaler,
        "feature_names": feature_names,
        "classes": list(calibrated_model.classes_),
        "cv_accuracy": mean_acc,
        "literature_baseline": "Leroux et al. (2018) + 2 class extension (Email, ICMP)",
    }

    joblib.dump(bundle, output_path)
    print(f"Model successfully saved to {output_path}")
    return bundle


if __name__ == "__main__":
    from typing import Tuple
    train_and_save_model()
