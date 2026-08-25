"""
Calibrated Machine Learning Traffic Classifier.
Classifies encrypted ESP flows into 6 traffic categories using flow statistical features.
Produces true calibrated confidence probabilities from predict_proba / CalibratedClassifierCV.
Zero hand-typed confidence values.
"""

import os
import joblib
import numpy as np
from typing import Dict, List, Any, Optional, Tuple


class ESPTrafficClassifier:
    """
    Calibrated Random Forest / Ensemble classifier for encrypted IPsec VPN flows.
    """

    CATEGORIES = [
        "VoIP",
        "Web Browsing",
        "Video Streaming",
        "ICMP",
        "Email",
        "WhatsApp",
    ]

    MODEL_DIR = "engine/ml/model_artifacts"
    MODEL_FILE = "engine/ml/model_artifacts/ipsec_traffic_classifier.joblib"

    def __init__(self, model_path: Optional[str] = None, confidence_floor: float = 0.35):
        self.model_path = model_path or self.MODEL_FILE
        self.confidence_floor = confidence_floor
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.load_or_initialize_model()

    def load_or_initialize_model(self):
        """Loads saved joblib artifact or triggers inline training."""
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                self.model = bundle["model"]
                self.scaler = bundle["scaler"]
                self.feature_names = bundle["feature_names"]
                return
            except Exception:
                pass
        
        # If not on disk, auto-train on startup
        from engine.ml.train_model import train_and_save_model
        bundle = train_and_save_model(output_path=self.model_path)
        self.model = bundle["model"]
        self.scaler = bundle["scaler"]
        self.feature_names = bundle["feature_names"]

    def predict_flow(self, feature_vector: List[float], packet_count: int) -> Dict[str, Any]:
        """
        Runs calibrated inference on an extracted flow feature vector.
        """
        # Guardrail: Short Flow check
        if packet_count < 5:
            return {
                "predicted_class": "Insufficient Data",
                "calibrated_confidence": 0.0,
                "is_confident": False,
                "probabilities": {cat: 0.0 for cat in self.CATEGORIES},
                "status": "SHORT_FLOW_REJECTED",
                "message": f"Flow contains only {packet_count} packets — minimum 5 required for reliable statistical inference."
            }

        X = np.array([feature_vector])
        X_scaled = self.scaler.transform(X)

        # True calibrated probabilities from scikit-learn
        probs = self.model.predict_proba(X_scaled)[0]
        classes = self.model.classes_

        prob_dict = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}
        
        # Fill any missing categories with 0.0
        for cat in self.CATEGORIES:
            if cat not in prob_dict:
                prob_dict[cat] = 0.0

        top_idx = int(np.argmax(probs))
        top_class = str(classes[top_idx])
        top_conf = round(float(probs[top_idx]), 4)

        # Guardrail: Confidence Floor check
        if top_conf < self.confidence_floor:
            return {
                "predicted_class": "Unclassified / Low Confidence",
                "calibrated_confidence": top_conf,
                "is_confident": False,
                "probabilities": prob_dict,
                "status": "CONFIDENCE_FLOOR_TRIGGERED",
                "message": f"Top prediction '{top_class}' confidence ({top_conf*100:.1f}%) is below the statistical certainty threshold ({self.confidence_floor*100:.0f}%)."
            }

        return {
            "predicted_class": top_class,
            "calibrated_confidence": top_conf,
            "is_confident": True,
            "probabilities": prob_dict,
            "status": "SUCCESS",
            "message": f"Classified with {top_conf*100:.1f}% calibrated model confidence."
        }


if __name__ == "__main__":
    clf = ESPTrafficClassifier()
    print("Loaded classifier with categories:", clf.CATEGORIES)
