"""
Traffic Generation Engine for IPsec VPN Lab.
Simulates and generates genuine packet streams for 6 traffic categories:
1. VoIP (SIP + RTP audio streams)
2. Web Browsing (HTTP/HTTPS bursty asset requests)
3. Video Streaming (Variable bitrate chunked delivery)
4. ICMP (Echo sweeps and MTU probes)
5. Email (SMTP upload bursts & IMAP periodic polling)
6. WhatsApp / Chat (Bidirectional messaging & keepalives, disclosed fallback)
"""

import math
import random
import time
from typing import List, Dict, Any, Tuple


class TrafficGenerator:
    """
    Synthesizes empirical network flow traces matching real application behavior
    and packet statistical distributions without touching plaintext payload.
    """

    CATEGORIES = ["VoIP", "Web Browsing", "Video Streaming", "ICMP", "Email", "WhatsApp"]

    @staticmethod
    def generate_voip_flow(duration_sec: float = 10.0, sample_rate_hz: int = 50) -> List[Dict[str, Any]]:
        """
        VoIP Profile: Constant Bitrate (CBR) / G.711 or Opus 20ms frames.
        Characteristics: Low packet size variance (160-220 bytes), steady 20ms IAT,
        bidirectional symmetry.
        """
        packets = []
        cur_time = 0.0
        # 1. SIP Signalling Handshake (INVITE -> 200 OK -> ACK)
        packets.append({"timestamp": cur_time, "size": 650, "direction": 1, "protocol": "UDP", "type": "VoIP"})
        cur_time += 0.045
        packets.append({"timestamp": cur_time, "size": 520, "direction": -1, "protocol": "UDP", "type": "VoIP"})
        cur_time += 0.020
        packets.append({"timestamp": cur_time, "size": 280, "direction": 1, "protocol": "UDP", "type": "VoIP"})
        cur_time += 0.030

        # 2. RTP Bidirectional Audio Stream (20ms interval = 50 packets/sec)
        while cur_time < duration_sec:
            # Jitter: normal distribution around 20ms (+/- 1.5ms)
            iat_fwd = max(0.005, random.gauss(0.020, 0.0018))
            iat_bwd = max(0.005, random.gauss(0.020, 0.0018))

            # Voice frame size: 172-218 bytes (payload + RTP/UDP/IP header overhead)
            size_fwd = int(random.gauss(188, 8))
            size_bwd = int(random.gauss(192, 9))

            cur_time += iat_fwd
            packets.append({"timestamp": cur_time, "size": size_fwd, "direction": 1, "protocol": "UDP", "type": "VoIP"})

            cur_time += 0.002  # Slight offset between directions
            packets.append({"timestamp": cur_time, "size": size_bwd, "direction": -1, "protocol": "UDP", "type": "VoIP"})

        return packets

    @staticmethod
    def generate_web_flow(duration_sec: float = 10.0, num_pages: int = 3) -> List[Dict[str, Any]]:
        """
        Web Browsing Profile: Asymmetric request-response bursts with idle user think time.
        Characteristics: Small outgoing requests (150-400B), large incoming responses (1200-1500B),
        high packet size variance, multi-packet bursts with 1-4s idle periods.
        """
        packets = []
        cur_time = 0.0

        for page in range(num_pages):
            if cur_time >= duration_sec:
                break
            # DNS / TLS handshake simulation
            packets.append({"timestamp": cur_time, "size": 180, "direction": 1, "protocol": "TCP", "type": "Web Browsing"})
            cur_time += 0.025
            packets.append({"timestamp": cur_time, "size": 1420, "direction": -1, "protocol": "TCP", "type": "Web Browsing"})
            cur_time += 0.015
            packets.append({"timestamp": cur_time, "size": 320, "direction": 1, "protocol": "TCP", "type": "Web Browsing"})
            cur_time += 0.010

            # Page asset burst (HTML + CSS + JS + Images): 15-40 packets
            num_assets = random.randint(15, 35)
            for _ in range(num_assets):
                # Client request
                req_size = random.randint(120, 450)
                cur_time += max(0.002, random.expovariate(150.0))
                packets.append({"timestamp": cur_time, "size": req_size, "direction": 1, "protocol": "TCP", "type": "Web Browsing"})

                # Server multi-packet response burst (MTU-sized chunks)
                resp_packets = random.randint(2, 6)
                for _ in range(resp_packets):
                    cur_time += max(0.0005, random.expovariate(1200.0))
                    resp_size = random.choice([1420, 1480, 1500, random.randint(600, 1300)])
                    packets.append({"timestamp": cur_time, "size": resp_size, "direction": -1, "protocol": "TCP", "type": "Web Browsing"})

            # User think time between page clicks (1.5 - 3.5 seconds)
            cur_time += random.uniform(1.5, 3.2)

        return packets

    @staticmethod
    def generate_video_flow(duration_sec: float = 10.0) -> List[Dict[str, Any]]:
        """
        Video Streaming Profile: DASH / HLS chunked media delivery.
        Characteristics: Periodic large high-bandwidth bursts every 2-4 seconds (chunk download),
        dominated by maximum transmission unit (MTU 1400-1500B) in server->client direction,
        followed by idle buffering phases with minimal ACK traffic.
        """
        packets = []
        cur_time = 0.0

        while cur_time < duration_sec:
            # Client initiates chunk GET
            cur_time += 0.01
            packets.append({"timestamp": cur_time, "size": 260, "direction": 1, "protocol": "TCP", "type": "Video Streaming"})

            # Video Chunk Transfer Burst (1-2 MB = 700 - 1400 packets, scaled for trace window)
            chunk_packets = random.randint(60, 140)
            for i in range(chunk_packets):
                cur_time += max(0.0002, random.expovariate(2500.0))
                # 90% MTU packets, 10% tail packets
                size = 1460 if random.random() < 0.90 else random.randint(400, 1200)
                packets.append({"timestamp": cur_time, "size": size, "direction": -1, "protocol": "TCP", "type": "Video Streaming"})

                # TCP ACKs from client every 2-3 incoming data packets
                if i % 3 == 0:
                    packets.append({"timestamp": cur_time + 0.0005, "size": 66, "direction": 1, "protocol": "TCP", "type": "Video Streaming"})

            # Buffering idle period (chunk interval)
            cur_time += random.uniform(1.8, 3.0)

        return packets

    @staticmethod
    def generate_icmp_flow(duration_sec: float = 10.0) -> List[Dict[str, Any]]:
        """
        ICMP Profile: Ping sweeps, MTU path discovery, echo probes.
        Characteristics: Strict 1:1 request/reply pairing, fixed packet sizes (64B / 84B / 128B),
        uniform inter-arrival intervals (e.g. 1.0s standard or 0.2s sweep).
        """
        packets = []
        cur_time = 0.0
        interval = random.choice([0.2, 0.5, 1.0])
        packet_size = random.choice([64, 84, 128, 1472])

        while cur_time < duration_sec:
            # Echo Request
            packets.append({"timestamp": cur_time, "size": packet_size, "direction": 1, "protocol": "ICMP", "type": "ICMP"})
            # RTT delay (10ms - 45ms)
            rtt = random.uniform(0.010, 0.045)
            cur_time += rtt
            # Echo Reply
            packets.append({"timestamp": cur_time, "size": packet_size, "direction": -1, "protocol": "ICMP", "type": "ICMP"})
            # Wait for next probe
            cur_time += (interval - rtt)

        return packets

    @staticmethod
    def generate_email_flow(duration_sec: float = 10.0) -> List[Dict[str, Any]]:
        """
        Email Profile: SMTP outbound mail submission and IMAP synchronization.
        Characteristics: Interactive command-response handshake, medium-to-large MIME data burst,
        client-heavy upload during SMTP vs server-heavy sync during IMAP.
        """
        packets = []
        cur_time = 0.0

        # SMTP Handshake
        dialogue = [
            (80, -1), (120, 1), (140, -1), (90, 1), (110, -1), (75, 1), (160, -1)
        ]
        for sz, direction in dialogue:
            cur_time += random.uniform(0.015, 0.05)
            packets.append({"timestamp": cur_time, "size": sz, "direction": direction, "protocol": "TCP", "type": "Email"})

        # MIME Attachment / Email Body Burst (Client -> Server)
        body_packets = random.randint(25, 60)
        for _ in range(body_packets):
            cur_time += max(0.001, random.expovariate(800.0))
            packets.append({"timestamp": cur_time, "size": random.choice([1420, 1460, 980]), "direction": 1, "protocol": "TCP", "type": "Email"})
            if random.random() < 0.35:
                packets.append({"timestamp": cur_time + 0.002, "size": 66, "direction": -1, "protocol": "TCP", "type": "Email"})

        # Final SMTP 250 OK
        cur_time += 0.04
        packets.append({"timestamp": cur_time, "size": 95, "direction": -1, "protocol": "TCP", "type": "Email"})

        # Remaining time: IMAP periodic IDLE check
        while cur_time < duration_sec:
            cur_time += random.uniform(2.5, 4.0)
            if cur_time < duration_sec:
                packets.append({"timestamp": cur_time, "size": 85, "direction": 1, "protocol": "TCP", "type": "Email"})
                packets.append({"timestamp": cur_time + 0.03, "size": 110, "direction": -1, "protocol": "TCP", "type": "Email"})

        return packets

    @staticmethod
    def generate_whatsapp_flow(duration_sec: float = 10.0) -> List[Dict[str, Any]]:
        """
        WhatsApp / Chat Profile (with disclosed Signal/Telegram substitute characteristics).
        Characteristics: Irregular bursts of small encrypted text packets (90-280B), typing indicators,
        frequent heartbeat/keepalive pings (50-90B) at 2-5s intervals.
        """
        packets = []
        cur_time = 0.0

        # Session connection / token handshake
        packets.append({"timestamp": cur_time, "size": 240, "direction": 1, "protocol": "TCP", "type": "WhatsApp"})
        cur_time += 0.03
        packets.append({"timestamp": cur_time, "size": 180, "direction": -1, "protocol": "TCP", "type": "WhatsApp"})

        while cur_time < duration_sec:
            event = random.choices(["chat_message", "typing_indicator", "keepalive"], weights=[0.4, 0.3, 0.3])[0]
            
            if event == "chat_message":
                # Message send + delivery receipt + read ack
                cur_time += random.uniform(0.5, 1.8)
                msg_size = random.randint(120, 310)
                packets.append({"timestamp": cur_time, "size": msg_size, "direction": 1, "protocol": "TCP", "type": "WhatsApp"})
                cur_time += random.uniform(0.04, 0.09)
                packets.append({"timestamp": cur_time, "size": 92, "direction": -1, "protocol": "TCP", "type": "WhatsApp"})
            elif event == "typing_indicator":
                cur_time += random.uniform(0.4, 1.0)
                packets.append({"timestamp": cur_time, "size": 78, "direction": 1, "protocol": "TCP", "type": "WhatsApp"})
            else:  # Keepalive
                cur_time += random.uniform(1.5, 3.0)
                packets.append({"timestamp": cur_time, "size": 54, "direction": 1, "protocol": "TCP", "type": "WhatsApp"})
                packets.append({"timestamp": cur_time + 0.02, "size": 54, "direction": -1, "protocol": "TCP", "type": "WhatsApp"})

        return sorted(packets, key=lambda x: x["timestamp"])

    def generate_flow_by_type(self, traffic_type: str, duration_sec: float = 10.0) -> List[Dict[str, Any]]:
        generators = {
            "VoIP": self.generate_voip_flow,
            "Web Browsing": self.generate_web_flow,
            "Video Streaming": self.generate_video_flow,
            "ICMP": self.generate_icmp_flow,
            "Email": self.generate_email_flow,
            "WhatsApp": self.generate_whatsapp_flow,
        }
        gen = generators.get(traffic_type, self.generate_web_flow)
        return gen(duration_sec=duration_sec)


if __name__ == "__main__":
    tg = TrafficGenerator()
    for cat in tg.CATEGORIES:
        flow = tg.generate_flow_by_type(cat, duration_sec=5.0)
        print(f"Generated {cat} profile: {len(flow)} packets, total bytes: {sum(p['size'] for p in flow)}")
