"""
Dataset & PCAP Synthesis Pipeline for IPsec VPN Security Audit & Classification.
Generates genuine PCAP captures across the full Matrix x 6-Traffic-Types,
with real Scapy IKEv2 / ESP packet structures and ground-truth metadata.
"""

import os
import json
import random
import struct
import time
from typing import Dict, List, Any, Optional

from scapy.all import (
    IP, UDP, Ether, Raw, wrpcap, Packet
)
from scapy.layers.ipsec import ESP

from testbed.matrix_generator import IPsecMatrixGenerator
from testbed.traffic_generators import TrafficGenerator


class IPsecPCAPGenerator:
    """
    Builds standards-compliant IKEv2 and ESP PCAP files with exact binary headers
    for deterministic parsing and ML feature extraction.
    """

    # IKEv2 Constants (RFC 7296, RFC 8247, RFC 9370)
    EXCHANGE_IKE_SA_INIT = 34
    EXCHANGE_IKE_INTERMEDIATE = 43  # RFC 9370 PQC
    EXCHANGE_IKE_AUTH = 35
    EXCHANGE_CREATE_CHILD_SA = 36
    EXCHANGE_INFORMATIONAL = 37

    # Payload Types
    PAYLOAD_SA = 33
    PAYLOAD_KE = 34
    PAYLOAD_NONCE = 40
    PAYLOAD_NOTIFY = 41
    PAYLOAD_VENDOR_ID = 43
    PAYLOAD_ENCRYPTED = 46

    # Transform Types
    TRANSFORM_ENCR = 1
    TRANSFORM_PRF = 2
    TRANSFORM_INTEG = 3
    TRANSFORM_DH = 4
    TRANSFORM_ESN = 5

    # Algorithm IDs
    TRANSFORMS_DB = {
        "aes256-sha384-ecp384-ke1_mlkem768": {
            "encr": (14, 256),  # AES-CBC-256
            "prf": 5,           # PRF_HMAC_SHA2_384
            "integ": 13,        # AUTH_HMAC_SHA2_384_192
            "dh": 20,           # ECP-384
            "pqc_ke": 0x4d4c,   # ML-KEM-768 (draft-ietf-ipsecme-ikev2-mlkem)
            "is_pqc": True,
            "dh_name": "ML-KEM-768 + ECP-384 (Hybrid)",
        },
        "aes256gcm16-prfsha384-ecp384": {
            "encr": (20, 256),  # AES-GCM-256 (16 octet ICV)
            "prf": 5,           # PRF_HMAC_SHA2_384
            "integ": 0,         # None (AEAD)
            "dh": 20,           # ECP-384
            "is_pqc": False,
            "dh_name": "ECP-384 (Group 20)",
        },
        "aes256-sha256-modp2048": {
            "encr": (12, 256),  # AES-CBC-256
            "prf": 4,           # PRF_HMAC_SHA2_256
            "integ": 12,        # AUTH_HMAC_SHA2_256_128
            "dh": 14,           # MODP-2048
            "is_pqc": False,
            "dh_name": "MODP-2048 (Group 14)",
        },
        "aes128-sha256-modp2048": {
            "encr": (12, 128),  # AES-CBC-128
            "prf": 4,           # PRF_HMAC_SHA2_256
            "integ": 12,        # AUTH_HMAC_SHA2_256_128
            "dh": 14,           # MODP-2048
            "is_pqc": False,
            "dh_name": "MODP-2048 (Group 14)",
        },
        "3des-md5-modp1024": {
            "encr": (3, 0),     # 3DES-CBC
            "prf": 1,           # PRF_HMAC_MD5
            "integ": 1,         # AUTH_HMAC_MD5_96
            "dh": 2,            # MODP-1024 (Insecure)
            "is_pqc": False,
            "dh_name": "MODP-1024 (Group 2)",
        },
        "aes128gcm16-prfsha256-ecp256": {
            "encr": (20, 128),  # AES-GCM-128
            "prf": 4,           # PRF_HMAC_SHA2_256
            "integ": 0,         # None (AEAD)
            "dh": 19,           # ECP-256
            "is_pqc": False,
            "dh_name": "ECP-256 (Group 19)",
        }
    }

    # Known Vendor IDs
    VENDOR_IDS = {
        "strongSwan": b"\x88\x2f\x0e\x6d\x59\xc6\x36\x79\x44\x40\x1f\x12\x68\x90\x40\xf2",
        "RFC 3947 (NAT-T)": b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f",
        "Cisco Unity": b"\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00",
    }

    def __init__(self, output_dir: str = "dataset/samples"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.traffic_gen = TrafficGenerator()

    def build_ikev2_header(
        self,
        spi_i: bytes,
        spi_r: bytes,
        next_payload: int,
        exchange_type: int,
        flags: int,
        msg_id: int,
        payload_bytes: bytes
    ) -> bytes:
        """Constructs a 28-byte IKEv2 RFC 7296 Header."""
        length = 28 + len(payload_bytes)
        version = (2 << 4) | 0  # Major=2, Minor=0
        header = struct.pack("!8s8sBBBBII", spi_i, spi_r, next_payload, version, exchange_type, flags, msg_id, length)
        return header + payload_bytes

    def build_sa_payload(self, suite_key: str, next_payload: int = 0) -> bytes:
        """Constructs an SA proposal payload."""
        suite = self.TRANSFORMS_DB.get(suite_key, self.TRANSFORMS_DB["aes256gcm16-prfsha384-ecp384"])
        transforms = []

        # 1. ENCR
        encr_id, key_len = suite["encr"]
        if key_len > 0:
            # Attribute: Key Length = key_len (AF=1, Type=14, Val=key_len)
            attr = struct.pack("!HH", 0x800E, key_len)
            tr_len = 8 + len(attr)
            tr_bytes = struct.pack("!BBHH", 3, 0, tr_len, self.TRANSFORM_ENCR) + struct.pack("!H", encr_id) + attr
        else:
            tr_len = 8
            tr_bytes = struct.pack("!BBHH", 3, 0, tr_len, self.TRANSFORM_ENCR) + struct.pack("!H", encr_id)
        transforms.append(tr_bytes)

        # 2. PRF
        prf_id = suite["prf"]
        transforms.append(struct.pack("!BBHHH", 3, 0, 8, self.TRANSFORM_PRF, prf_id))

        # 3. INTEG (if present)
        if suite["integ"] > 0:
            transforms.append(struct.pack("!BBHHH", 3, 0, 8, self.TRANSFORM_INTEG, suite["integ"]))

        # 4. DH Group
        dh_id = suite["dh"]
        transforms.append(struct.pack("!BBHHH", 0, 0, 8, self.TRANSFORM_DH, dh_id))

        # Pack Proposal (Proposal #1, Protocol IKE=1, SPI size=0)
        proposal_content = b"".join(transforms)
        prop_len = 8 + len(proposal_content)
        proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, len(transforms)) + proposal_content

        # SA Payload header
        sa_payload_len = 4 + len(proposal)
        sa_hdr = struct.pack("!BBH", next_payload, 0, sa_payload_len)
        return sa_hdr + proposal

    def build_ke_payload(self, dh_group: int, key_size: int = 96, next_payload: int = 0) -> bytes:
        """Constructs a Key Exchange payload."""
        ke_data = os.urandom(key_size)
        ke_len = 8 + len(ke_data)
        ke_hdr = struct.pack("!BBHH", next_payload, 0, ke_len, dh_group)
        return ke_hdr + struct.pack("!H", 0) + ke_data  # Reserved 2B

    def build_pqc_intermediate_payload(self, next_payload: int = 0) -> bytes:
        """Constructs an RFC 9370 Additional Key Exchange payload carrying ML-KEM-768."""
        mlkem_pubkey = os.urandom(1184)  # ML-KEM-768 public key size
        ke_len = 8 + len(mlkem_pubkey)
        # Transform ID for ML-KEM-768 = 0x4D4C (or custom RFC 9370 KE ID)
        ke_hdr = struct.pack("!BBHH", next_payload, 0, ke_len, 0x4D4C)
        return ke_hdr + struct.pack("!H", 0) + mlkem_pubkey

    def build_nonce_payload(self, next_payload: int = 0) -> bytes:
        nonce_data = os.urandom(32)
        nonce_len = 4 + len(nonce_data)
        return struct.pack("!BBH", next_payload, 0, nonce_len) + nonce_data

    def build_vendor_id_payload(self, vendor_name: str, next_payload: int = 0) -> bytes:
        vid = self.VENDOR_IDS.get(vendor_name, os.urandom(16))
        vid_len = 4 + len(vid)
        return struct.pack("!BBH", next_payload, 0, vid_len) + vid

    def build_encrypted_auth_payload(self, next_payload: int = 0, length: int = 160) -> bytes:
        """Constructs Encrypted and Authenticated Payload (SK payload)."""
        enc_data = os.urandom(length)
        payload_len = 4 + len(enc_data)
        return struct.pack("!BBH", next_payload, 0, payload_len) + enc_data

    def generate_full_session_pcap(
        self,
        suite_id: str,
        traffic_type: str,
        filename: str,
        duration_sec: float = 6.0,
        src_ip: str = "10.10.0.2",
        dst_ip: str = "10.10.0.3",
        spi_esp: int = 0xC01A2026
    ) -> Dict[str, Any]:
        """
        Synthesizes an authentic PCAP file containing IKEv2 negotiation + ESP data flow.
        """
        packets = []
        cur_time = time.time() - 3600.0  # Stable baseline timestamp
        spi_i = os.urandom(8)
        spi_r = os.urandom(8)

        suite_meta = IPsecMatrixGenerator.CIPHER_SUITES[0]
        for s in IPsecMatrixGenerator.CIPHER_SUITES:
            if s["id"] == suite_id:
                suite_meta = s
                break

        suite_key = suite_meta.get("ike_proposal", "aes256gcm16-prfsha384-ecp384!").replace("!", "")
        is_pqc = "mlkem" in suite_key
        suite_obj = self.TRANSFORMS_DB.get(suite_key, self.TRANSFORMS_DB["aes256gcm16-prfsha384-ecp384"])
        dh_grp_num = suite_obj.get("dh", 14)
        ke_size = 96 if dh_grp_num in (19, 20) else 128 if dh_grp_num == 2 else 256

        # -------------------------------------------------------------
        # 1. IKE_SA_INIT Request (Initiator -> Responder)
        # Payloads: SA -> KE -> Nonce -> VendorID (strongSwan)
        # -------------------------------------------------------------
        vid_p = self.build_vendor_id_payload("strongSwan", next_payload=0)
        nonce_p = self.build_nonce_payload(next_payload=self.PAYLOAD_VENDOR_ID)
        ke_p = self.build_ke_payload(dh_group=dh_grp_num, key_size=ke_size, next_payload=self.PAYLOAD_NONCE)
        sa_p = self.build_sa_payload(suite_key, next_payload=self.PAYLOAD_KE)

        init_payloads = sa_p + ke_p + nonce_p + vid_p
        ike_init_req = self.build_ikev2_header(
            spi_i=spi_i,
            spi_r=b"\x00" * 8,
            next_payload=self.PAYLOAD_SA,
            exchange_type=self.EXCHANGE_IKE_SA_INIT,
            flags=0x08,  # Initiator bit
            msg_id=0,
            payload_bytes=init_payloads
        )

        pkt1 = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / Raw(load=ike_init_req)
        pkt1.time = cur_time
        packets.append(pkt1)

        # -------------------------------------------------------------
        # 2. IKE_SA_INIT Response (Responder -> Initiator)
        # -------------------------------------------------------------
        cur_time += 0.024
        resp_sa_p = self.build_sa_payload(suite_key, next_payload=self.PAYLOAD_KE)
        resp_ke_p = self.build_ke_payload(dh_group=dh_grp_num, key_size=ke_size, next_payload=self.PAYLOAD_NONCE)
        resp_nonce_p = self.build_nonce_payload(next_payload=self.PAYLOAD_VENDOR_ID)
        resp_vid_p = self.build_vendor_id_payload("strongSwan", next_payload=0)

        resp_payloads = resp_sa_p + resp_ke_p + resp_nonce_p + resp_vid_p
        ike_init_resp = self.build_ikev2_header(
            spi_i=spi_i,
            spi_r=spi_r,
            next_payload=self.PAYLOAD_SA,
            exchange_type=self.EXCHANGE_IKE_SA_INIT,
            flags=0x20,  # Response bit
            msg_id=0,
            payload_bytes=resp_payloads
        )

        pkt2 = Ether() / IP(src=dst_ip, dst=src_ip) / UDP(sport=500, dport=500) / Raw(load=ike_init_resp)
        pkt2.time = cur_time
        packets.append(pkt2)

        # -------------------------------------------------------------
        # 3. PQC Intermediate Exchange (RFC 9370) if ML-KEM is used
        # -------------------------------------------------------------
        if is_pqc:
            cur_time += 0.035
            pqc_req = self.build_pqc_intermediate_payload(next_payload=0)
            ike_inter_req = self.build_ikev2_header(
                spi_i=spi_i,
                spi_r=spi_r,
                next_payload=self.PAYLOAD_KE,
                exchange_type=self.EXCHANGE_IKE_INTERMEDIATE,
                flags=0x08,
                msg_id=1,
                payload_bytes=pqc_req
            )
            pkt_pqc1 = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / Raw(load=ike_inter_req)
            pkt_pqc1.time = cur_time
            packets.append(pkt_pqc1)

            cur_time += 0.040
            pqc_resp = self.build_pqc_intermediate_payload(next_payload=0)
            ike_inter_resp = self.build_ikev2_header(
                spi_i=spi_i,
                spi_r=spi_r,
                next_payload=self.PAYLOAD_KE,
                exchange_type=self.EXCHANGE_IKE_INTERMEDIATE,
                flags=0x20,
                msg_id=1,
                payload_bytes=pqc_resp
            )
            pkt_pqc2 = Ether() / IP(src=dst_ip, dst=src_ip) / UDP(sport=500, dport=500) / Raw(load=ike_inter_resp)
            pkt_pqc2.time = cur_time
            packets.append(pkt_pqc2)

        # -------------------------------------------------------------
        # 4. IKE_AUTH Exchange (Encrypted Child SA establishment)
        # -------------------------------------------------------------
        auth_msg_id = 2 if is_pqc else 1
        cur_time += 0.030
        auth_req_payload = self.build_encrypted_auth_payload(next_payload=0, length=240)
        ike_auth_req = self.build_ikev2_header(
            spi_i=spi_i,
            spi_r=spi_r,
            next_payload=self.PAYLOAD_ENCRYPTED,
            exchange_type=self.EXCHANGE_IKE_AUTH,
            flags=0x08,
            msg_id=auth_msg_id,
            payload_bytes=auth_req_payload
        )
        pkt3 = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00\x00\x00\x00" + ike_auth_req)
        pkt3.time = cur_time
        packets.append(pkt3)

        cur_time += 0.025
        auth_resp_payload = self.build_encrypted_auth_payload(next_payload=0, length=210)
        ike_auth_resp = self.build_ikev2_header(
            spi_i=spi_i,
            spi_r=spi_r,
            next_payload=self.PAYLOAD_ENCRYPTED,
            exchange_type=self.EXCHANGE_IKE_AUTH,
            flags=0x20,
            msg_id=auth_msg_id,
            payload_bytes=auth_resp_payload
        )
        pkt4 = Ether() / IP(src=dst_ip, dst=src_ip) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00\x00\x00\x00" + ike_auth_resp)
        pkt4.time = cur_time
        packets.append(pkt4)

        # -------------------------------------------------------------
        # 5. Encrypted ESP Traffic Stream (matching chosen traffic_type)
        # -------------------------------------------------------------
        flow_packets = self.traffic_gen.generate_flow_by_type(traffic_type, duration_sec=duration_sec)
        base_flow_time = cur_time + 0.05
        seq_fwd = 1
        seq_bwd = 1

        for p_meta in flow_packets:
            p_time = base_flow_time + p_meta["timestamp"]
            is_forward = (p_meta["direction"] == 1)
            p_src = src_ip if is_forward else dst_ip
            p_dst = dst_ip if is_forward else src_ip
            p_seq = seq_fwd if is_forward else seq_bwd
            if is_forward:
                seq_fwd += 1
            else:
                seq_bwd += 1

            # Build authentic ESP packet: ESP header + encrypted payload padding
            payload_len = max(16, p_meta["size"] - 40)  # minus IP/ESP headers
            esp_layer = ESP(spi=spi_esp, seq=p_seq, data=os.urandom(payload_len))
            
            # Encapsulate in IP / ESP
            pkt_esp = Ether() / IP(src=p_src, dst=p_dst, proto=50) / esp_layer
            pkt_esp.time = p_time
            packets.append(pkt_esp)

        # Sort all packets by timestamp
        packets.sort(key=lambda x: x.time)

        # Write to PCAP file
        filepath = os.path.join(self.output_dir, filename)
        wrpcap(filepath, packets)

        metadata = {
            "filename": filename,
            "filepath": filepath,
            "suite_id": suite_id,
            "suite_name": suite_meta["name"],
            "traffic_type": traffic_type,
            "packet_count": len(packets),
            "esp_packet_count": len(flow_packets),
            "ike_version": 2,
            "is_pqc": is_pqc,
            "security_tier": suite_meta["security_tier"],
            "nist_status": suite_meta["nist_status"],
            "dh_group": suite_meta["dh_group"],
            "mode": suite_meta["mode"],
            "pfs": suite_meta["pfs"],
        }

        meta_path = filepath.replace(".pcap", ".json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return metadata

    def generate_benchmark_dataset(self) -> List[Dict[str, Any]]:
        """
        Builds the standard sample dataset library for the offline evaluator.
        """
        samples = [
            ("pqc_hybrid_quantum_safe", "VoIP", "sample_pqc_mlkem768_voip.pcap"),
            ("nist_approved_aes_gcm_256", "Web Browsing", "sample_nist_approved_web.pcap"),
            ("nist_standard_aes_cbc_256", "Video Streaming", "sample_nist_standard_video.pcap"),
            ("legacy_acceptable_aes_128", "ICMP", "sample_legacy_no_pfs_icmp.pcap"),
            ("insecure_deprecated_3des_md5", "Email", "sample_deprecated_3des_email.pcap"),
            ("transport_mode_aes_gcm", "WhatsApp", "sample_transport_mode_whatsapp.pcap"),
        ]

        generated = []
        for suite_id, traffic_type, fname in samples:
            meta = self.generate_full_session_pcap(suite_id, traffic_type, fname, duration_sec=5.0)
            generated.append(meta)

        return generated


if __name__ == "__main__":
    gen = IPsecPCAPGenerator()
    results = gen.generate_benchmark_dataset()
    print(f"Generated {len(results)} standard benchmark PCAPs in dataset/samples/")
