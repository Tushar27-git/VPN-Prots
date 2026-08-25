"""
Unit tests for Deterministic IKE Parser and Fingerprinter.
"""

import os
import pytest
from engine.protocol.ike_parser import DeterministicIKEParser
from engine.protocol.fingerprinter import ImplementationFingerprinter


@pytest.fixture
def parser():
    return DeterministicIKEParser()


@pytest.fixture
def fingerprinter():
    return ImplementationFingerprinter()


def test_parser_on_pqc_sample(parser, fingerprinter):
    pcap_path = "dataset/samples/sample_pqc_mlkem768_voip.pcap"
    assert os.path.exists(pcap_path), "PQC benchmark sample must exist"

    result = parser.parse_pcap_file(pcap_path)
    assert result["summary"]["total_packets"] > 0
    assert result["summary"]["ike_packet_count"] >= 2
    assert result["summary"]["esp_packet_count"] > 0
    assert result["summary"]["pqc_ready"] is True
    assert "ML-KEM" in result["summary"]["dh_group"] or "ECP" in result["summary"]["dh_group"]

    fp = fingerprinter.fingerprint_session(result)
    assert "strongSwan" in fp["vendor"]
    assert fp["confidence"] > 0.8


def test_parser_on_deprecated_sample(parser):
    pcap_path = "dataset/samples/sample_deprecated_3des_email.pcap"
    assert os.path.exists(pcap_path), "Deprecated benchmark sample must exist"

    result = parser.parse_pcap_file(pcap_path)
    assert result["summary"]["total_packets"] > 0
    assert "3DES" in result["summary"]["encryption_algorithm"]
    assert "1024-bit MODP" in result["summary"]["dh_group"]
    assert result["summary"]["pqc_ready"] is False
