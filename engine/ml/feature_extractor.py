"""
ESP Flow Feature Extractor.
Extracts statistical distribution, timing, directional, and burst features
from encrypted ESP packet streams without inspecting encrypted payload bytes.
Methodology grounded in Leroux et al. (2018), extended to 6 traffic classes.
"""

import math
from typing import Dict, List, Any, Optional
import numpy as np


class ESPFlowFeatureExtractor:
    """
    Computes statistical feature vectors across encrypted ESP biflows.
    Zero payload inspection — 100% metadata and timing distribution based.
    """

    FEATURE_NAMES = [
        "pkt_count_total",
        "pkt_count_fwd",
        "pkt_count_bwd",
        "bytes_total",
        "bytes_fwd",
        "bytes_bwd",
        "fwd_bwd_pkt_ratio",
        "fwd_bwd_byte_ratio",
        "pkt_size_mean",
        "pkt_size_std",
        "pkt_size_min",
        "pkt_size_max",
        "pkt_size_median",
        "pkt_size_p25",
        "pkt_size_p75",
        "pkt_size_p90",
        "fwd_pkt_size_mean",
        "fwd_pkt_size_std",
        "bwd_pkt_size_mean",
        "bwd_pkt_size_std",
        "duration_sec",
        "iat_mean",
        "iat_std",
        "iat_min",
        "iat_max",
        "iat_median",
        "fwd_iat_mean",
        "fwd_iat_std",
        "bwd_iat_mean",
        "bwd_iat_std",
        "burst_count",
        "burst_pkt_mean",
        "burst_pkt_max",
        "burst_bytes_mean",
        "burst_duration_mean",
        "idle_time_mean",
    ]

    def __init__(self, burst_threshold_sec: float = 0.050):
        self.burst_threshold_sec = burst_threshold_sec

    def extract_features_from_packets(
        self,
        esp_packets: List[Dict[str, Any]],
        initiator_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extracts statistical feature dictionary and flat numeric vector from parsed ESP packet records.
        Each record has: {"time": float, "src_ip": str, "dst_ip": str, "length": int, "spi": str, "seq": int}
        """
        if not esp_packets or len(esp_packets) < 2:
            return {"error": "Insufficient ESP packets (minimum 2 required)", "features": None, "vector": None}

        # Sort by timestamp
        sorted_pkts = sorted(esp_packets, key=lambda x: x["time"])
        
        # Determine initiator IP if not given
        if not initiator_ip:
            initiator_ip = sorted_pkts[0]["src_ip"]

        times = np.array([p["time"] for p in sorted_pkts])
        sizes = np.array([p["length"] for p in sorted_pkts], dtype=float)
        directions = np.array([1 if p["src_ip"] == initiator_ip else -1 for p in sorted_pkts])

        fwd_mask = (directions == 1)
        bwd_mask = (directions == -1)

        fwd_sizes = sizes[fwd_mask] if np.any(fwd_mask) else np.array([0.0])
        bwd_sizes = sizes[bwd_mask] if np.any(bwd_mask) else np.array([0.0])

        total_pkts = len(sorted_pkts)
        fwd_pkts = int(np.sum(fwd_mask))
        bwd_pkts = int(np.sum(bwd_mask))

        total_bytes = float(np.sum(sizes))
        fwd_bytes = float(np.sum(fwd_sizes))
        bwd_bytes = float(np.sum(bwd_sizes))

        pkt_ratio = fwd_pkts / max(1, bwd_pkts)
        byte_ratio = fwd_bytes / max(1.0, bwd_bytes)

        duration = max(0.001, float(times[-1] - times[0]))

        # Inter-arrival times
        iats = np.diff(times) if len(times) > 1 else np.array([0.0])
        fwd_times = times[fwd_mask]
        bwd_times = times[bwd_mask]

        fwd_iats = np.diff(fwd_times) if len(fwd_times) > 1 else np.array([0.0])
        bwd_iats = np.diff(bwd_times) if len(bwd_times) > 1 else np.array([0.0])

        # Burst dynamics calculation
        bursts = []
        cur_burst = [sorted_pkts[0]]
        for i in range(1, len(sorted_pkts)):
            dt = sorted_pkts[i]["time"] - sorted_pkts[i-1]["time"]
            if dt <= self.burst_threshold_sec:
                cur_burst.append(sorted_pkts[i])
            else:
                bursts.append(cur_burst)
                cur_burst = [sorted_pkts[i]]
        if cur_burst:
            bursts.append(cur_burst)

        burst_pkts = [len(b) for b in bursts]
        burst_bytes = [sum(p["length"] for p in b) for b in bursts]
        burst_durations = [max(0.0001, b[-1]["time"] - b[0]["time"]) for b in bursts]
        
        # Idle times between bursts
        idle_times = []
        for i in range(1, len(bursts)):
            idle_dt = bursts[i][0]["time"] - bursts[i-1][-1]["time"]
            idle_times.append(max(0.0, idle_dt))
        if not idle_times:
            idle_times = [0.0]

        feat_dict = {
            "pkt_count_total": float(total_pkts),
            "pkt_count_fwd": float(fwd_pkts),
            "pkt_count_bwd": float(bwd_pkts),
            "bytes_total": float(total_bytes),
            "bytes_fwd": float(fwd_bytes),
            "bytes_bwd": float(bwd_bytes),
            "fwd_bwd_pkt_ratio": float(pkt_ratio),
            "fwd_bwd_byte_ratio": float(byte_ratio),
            "pkt_size_mean": float(np.mean(sizes)),
            "pkt_size_std": float(np.std(sizes)),
            "pkt_size_min": float(np.min(sizes)),
            "pkt_size_max": float(np.max(sizes)),
            "pkt_size_median": float(np.median(sizes)),
            "pkt_size_p25": float(np.percentile(sizes, 25)),
            "pkt_size_p75": float(np.percentile(sizes, 75)),
            "pkt_size_p90": float(np.percentile(sizes, 90)),
            "fwd_pkt_size_mean": float(np.mean(fwd_sizes)),
            "fwd_pkt_size_std": float(np.std(fwd_sizes)),
            "bwd_pkt_size_mean": float(np.mean(bwd_sizes)),
            "bwd_pkt_size_std": float(np.std(bwd_sizes)),
            "duration_sec": float(duration),
            "iat_mean": float(np.mean(iats)),
            "iat_std": float(np.std(iats)),
            "iat_min": float(np.min(iats)),
            "iat_max": float(np.max(iats)),
            "iat_median": float(np.median(iats)),
            "fwd_iat_mean": float(np.mean(fwd_iats)),
            "fwd_iat_std": float(np.std(fwd_iats)),
            "bwd_iat_mean": float(np.mean(bwd_iats)),
            "bwd_iat_std": float(np.std(bwd_iats)),
            "burst_count": float(len(bursts)),
            "burst_pkt_mean": float(np.mean(burst_pkts)),
            "burst_pkt_max": float(np.max(burst_pkts)),
            "burst_bytes_mean": float(np.mean(burst_bytes)),
            "burst_duration_mean": float(np.mean(burst_durations)),
            "idle_time_mean": float(np.mean(idle_times)),
        }

        vector = [feat_dict[k] for k in self.FEATURE_NAMES]

        return {
            "features": feat_dict,
            "vector": vector,
            "feature_names": self.FEATURE_NAMES,
            "packet_count": total_pkts,
            "duration_sec": round(duration, 3),
        }


if __name__ == "__main__":
    from testbed.traffic_generators import TrafficGenerator
    tg = TrafficGenerator()
    pkts = tg.generate_voip_flow(duration_sec=3.0)
    esp_pkts = [{"time": p["timestamp"], "src_ip": "10.10.0.2" if p["direction"]==1 else "10.10.0.3", "dst_ip": "10.10.0.3" if p["direction"]==1 else "10.10.0.2", "length": p["size"], "spi": "0x1234", "seq": i} for i, p in enumerate(pkts)]
    extractor = ESPFlowFeatureExtractor()
    res = extractor.extract_features_from_packets(esp_pkts)
    print("Extracted", len(res["vector"]), "features. Mean packet size:", res["features"]["pkt_size_mean"])
