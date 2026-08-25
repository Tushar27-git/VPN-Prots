"""
Unit tests for ESP Flow Feature Extractor and Calibrated ML Classifier.
"""

import pytest
import numpy as np
from engine.ml.feature_extractor import ESPFlowFeatureExtractor
from engine.ml.classifier import ESPTrafficClassifier
from testbed.traffic_generators import TrafficGenerator


@pytest.fixture
def extractor():
    return ESPFlowFeatureExtractor()


@pytest.fixture
def classifier():
    return ESPTrafficClassifier()


def test_feature_extractor_on_voip(extractor):
    tg = TrafficGenerator()
    pkts = tg.generate_voip_flow(duration_sec=3.0)
    esp_records = [
        {"time": p["timestamp"], "src_ip": "10.10.0.2" if p["direction"] == 1 else "10.10.0.3", "dst_ip": "10.10.0.3" if p["direction"] == 1 else "10.10.0.2", "length": p["size"], "spi": "0x1234", "seq": i + 1}
        for i, p in enumerate(pkts)
    ]

    res = extractor.extract_features_from_packets(esp_records)
    assert res["vector"] is not None
    assert len(res["vector"]) == len(extractor.FEATURE_NAMES)
    assert res["features"]["pkt_count_total"] == len(pkts)
    assert res["features"]["pkt_size_mean"] > 100


def test_classifier_predictions(classifier, extractor):
    tg = TrafficGenerator()
    pkts = tg.generate_voip_flow(duration_sec=4.0)
    esp_records = [
        {"time": p["timestamp"], "src_ip": "10.10.0.2" if p["direction"] == 1 else "10.10.0.3", "dst_ip": "10.10.0.3" if p["direction"] == 1 else "10.10.0.2", "length": p["size"], "spi": "0x1234", "seq": i + 1}
        for i, p in enumerate(pkts)
    ]
    feat = extractor.extract_features_from_packets(esp_records)
    pred = classifier.predict_flow(feat["vector"], feat["packet_count"])

    assert pred["predicted_class"] == "VoIP"
    assert pred["calibrated_confidence"] > 0.60
    assert pred["is_confident"] is True
    # Probabilities must sum to ~1.0
    prob_sum = sum(pred["probabilities"].values())
    assert 0.98 <= prob_sum <= 1.02


def test_short_flow_guardrail(classifier, extractor):
    # Only 3 packets (under the 5 packet floor)
    esp_records = [
        {"time": 0.1 * i, "src_ip": "10.10.0.2", "dst_ip": "10.10.0.3", "length": 200, "spi": "0x1234", "seq": i + 1}
        for i in range(3)
    ]
    feat = extractor.extract_features_from_packets(esp_records)
    pred = classifier.predict_flow(feat["vector"], feat["packet_count"])

    assert pred["status"] == "SHORT_FLOW_REJECTED"
    assert pred["calibrated_confidence"] == 0.0
