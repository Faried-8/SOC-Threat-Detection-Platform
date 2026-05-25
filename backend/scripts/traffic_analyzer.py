"""
==============================================================================
Network Traffic Analysis & Threat Detection System
Module: Traffic Analyzer
Version: 2.0.0
==============================================================================

Description:
    Deep traffic analysis engine. Builds statistical profiles, behavioral
    baselines, timeline analysis, and top-talker reports from parsed packets.
    Output feeds both the report generator and visualization layer.
==============================================================================
"""

import logging
import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger("TrafficAnalyzer")


@dataclass
class TrafficProfile:
    """Comprehensive traffic statistical profile."""
    analysis_timestamp: str
    pcap_file: str
    capture_duration_seconds: float
    total_packets: int
    total_bytes: int
    avg_packet_size: float
    packets_per_second: float
    bytes_per_second: float

    # Protocol distribution
    protocol_distribution: Dict[str, int]
    protocol_percentages: Dict[str, float]

    # Top talkers
    top_src_ips: List[Tuple[str, int]]
    top_dst_ips: List[Tuple[str, int]]
    top_src_ports: List[Tuple[int, int]]
    top_dst_ports: List[Tuple[int, int]]
    top_ip_pairs: List[Tuple[str, int]]

    # DNS statistics
    top_queried_domains: List[Tuple[str, int]]
    unique_dns_queries: int
    dns_query_rate: float

    # HTTP statistics
    http_methods: Dict[str, int]
    top_http_hosts: List[Tuple[str, int]]
    http_status_codes: Dict[str, int]
    suspicious_user_agents: List[str]

    # Behavioral indicators
    syn_only_packets: int
    rst_packets: int
    connection_resets_ratio: float
    avg_ttl: float
    ttl_anomalies: int

    # Timeline
    traffic_timeline: Dict[str, int]    # minute → packet_count
    peak_traffic_minute: str
    quiet_periods: List[str]

    # Threat indicators
    suspicious_packet_ratio: float
    unique_suspicious_ips: int


class TrafficAnalyzer:
    """
    Comprehensive traffic analysis engine.
    Generates statistical baselines and behavioral profiles from packet data.
    """

    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def analyze(self, packets, pcap_file: str = "unknown") -> TrafficProfile:
        """Run full traffic analysis pipeline."""
        logger.info(f"[ANALYZE] Starting traffic analysis on {len(packets)} packets...")

        if not packets:
            raise ValueError("No packets provided for analysis")

        # ── Time Range ────────────────────────────────────────────────────────
        timestamps = []
        for p in packets:
            try:
                ts = datetime.fromisoformat(p.timestamp.replace("Z", ""))
                timestamps.append(ts)
            except Exception:
                pass

        duration = 0.0
        if len(timestamps) >= 2:
            duration = (max(timestamps) - min(timestamps)).total_seconds()

        # ── Byte / Size Stats ─────────────────────────────────────────────────
        total_bytes = sum(p.length for p in packets)
        avg_size = total_bytes / len(packets) if packets else 0
        pps = len(packets) / duration if duration > 0 else 0
        bps = total_bytes / duration if duration > 0 else 0

        # ── Protocol Distribution ─────────────────────────────────────────────
        proto_counts = Counter(p.protocol for p in packets)
        total = len(packets)
        proto_pct = {k: round(v / total * 100, 2) for k, v in proto_counts.items()}

        # ── Top Talkers ───────────────────────────────────────────────────────
        src_ip_counts = Counter(p.src_ip for p in packets)
        dst_ip_counts = Counter(p.dst_ip for p in packets)
        src_port_counts = Counter(p.src_port for p in packets if p.src_port)
        dst_port_counts = Counter(p.dst_port for p in packets if p.dst_port)
        pair_counts = Counter(f"{p.src_ip} → {p.dst_ip}" for p in packets)

        # ── DNS Analysis ──────────────────────────────────────────────────────
        dns_pkts = [p for p in packets if p.protocol == "DNS" and p.dns_query]
        domain_counts = Counter(p.dns_query for p in dns_pkts)
        dns_rate = len(dns_pkts) / duration if duration > 0 else 0

        # ── HTTP Analysis ─────────────────────────────────────────────────────
        http_pkts = [p for p in packets if p.protocol == "HTTP"]
        method_counts = Counter(p.http_method for p in http_pkts if p.http_method)
        host_counts = Counter(p.http_host for p in http_pkts if p.http_host)
        status_counts = Counter(p.http_status_code for p in http_pkts if p.http_status_code)
        sus_uas = list(set(
            p.http_user_agent for p in http_pkts
            if p.http_user_agent and p.is_suspicious
        ))

        # ── TCP Flag Analysis ─────────────────────────────────────────────────
        tcp_pkts = [p for p in packets if p.protocol == "TCP"]
        syn_only = sum(1 for p in tcp_pkts if p.flags == "SYN")
        rst_count = sum(1 for p in tcp_pkts if p.flags and "RST" in p.flags)
        rst_ratio = rst_count / len(tcp_pkts) if tcp_pkts else 0

        # ── TTL Analysis ──────────────────────────────────────────────────────
        ttl_values = [p.ttl for p in packets if p.ttl is not None]
        avg_ttl = sum(ttl_values) / len(ttl_values) if ttl_values else 0
        ttl_anomalies = sum(1 for t in ttl_values if t > 250 or t < 10)

        # ── Traffic Timeline (by minute) ──────────────────────────────────────
        timeline: Dict[str, int] = defaultdict(int)
        for ts in timestamps:
            minute_key = ts.strftime("%Y-%m-%d %H:%M")
            timeline[minute_key] += 1

        peak_minute = max(timeline, key=timeline.get) if timeline else "N/A"
        quiet = [m for m, c in timeline.items() if c < (pps * 30 * 0.1)]

        # ── Suspicious Traffic ────────────────────────────────────────────────
        sus_packets = [p for p in packets if p.is_suspicious]
        sus_ratio = len(sus_packets) / len(packets) if packets else 0
        sus_ips = set(p.src_ip for p in sus_packets)

        profile = TrafficProfile(
            analysis_timestamp=datetime.utcnow().isoformat(),
            pcap_file=pcap_file,
            capture_duration_seconds=round(duration, 2),
            total_packets=len(packets),
            total_bytes=total_bytes,
            avg_packet_size=round(avg_size, 2),
            packets_per_second=round(pps, 2),
            bytes_per_second=round(bps, 2),
            protocol_distribution=dict(proto_counts),
            protocol_percentages=proto_pct,
            top_src_ips=src_ip_counts.most_common(10),
            top_dst_ips=dst_ip_counts.most_common(10),
            top_src_ports=src_port_counts.most_common(10),
            top_dst_ports=dst_port_counts.most_common(10),
            top_ip_pairs=pair_counts.most_common(10),
            top_queried_domains=domain_counts.most_common(15),
            unique_dns_queries=len(domain_counts),
            dns_query_rate=round(dns_rate, 2),
            http_methods=dict(method_counts),
            top_http_hosts=host_counts.most_common(10),
            http_status_codes=dict(status_counts),
            suspicious_user_agents=sus_uas[:10],
            syn_only_packets=syn_only,
            rst_packets=rst_count,
            connection_resets_ratio=round(rst_ratio, 4),
            avg_ttl=round(avg_ttl, 2),
            ttl_anomalies=ttl_anomalies,
            traffic_timeline=dict(timeline),
            peak_traffic_minute=peak_minute,
            quiet_periods=quiet[:5],
            suspicious_packet_ratio=round(sus_ratio, 4),
            unique_suspicious_ips=len(sus_ips),
        )

        logger.info(
            f"[ANALYZE] Complete | {len(packets)} pkts | "
            f"{duration:.1f}s duration | "
            f"{len(proto_counts)} protocols | "
            f"{sus_ratio*100:.1f}% suspicious"
        )
        return profile

    def export_json(self, profile: TrafficProfile, filename: str = "traffic_analysis.json") -> str:
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            json.dump(asdict(profile), f, indent=2, default=str)
        logger.info(f"[EXPORT] Traffic analysis JSON: {path}")
        return path

    def print_summary(self, profile: TrafficProfile):
        """Print a formatted terminal summary."""
        divider = "=" * 70
        print(f"\n{divider}")
        print(f"  TRAFFIC ANALYSIS SUMMARY")
        print(f"  File: {profile.pcap_file}")
        print(f"  Analyzed: {profile.analysis_timestamp}")
        print(divider)
        print(f"\n  📦 VOLUME")
        print(f"     Total Packets   : {profile.total_packets:,}")
        print(f"     Total Bytes     : {profile.total_bytes:,} ({profile.total_bytes/1024/1024:.2f} MB)")
        print(f"     Duration        : {profile.capture_duration_seconds:.1f}s")
        print(f"     Packets/sec     : {profile.packets_per_second:.1f}")
        print(f"     Avg Packet Size : {profile.avg_packet_size:.0f} bytes")

        print(f"\n  🌐 PROTOCOL DISTRIBUTION")
        for proto, count in sorted(profile.protocol_distribution.items(), key=lambda x: -x[1]):
            pct = profile.protocol_percentages.get(proto, 0)
            bar = "█" * int(pct / 2)
            print(f"     {proto:<12} {count:>6} pkts  {pct:>5.1f}%  {bar}")

        print(f"\n  🏆 TOP SOURCE IPs")
        for ip, count in profile.top_src_ips[:5]:
            print(f"     {ip:<20} {count:>6} packets")

        print(f"\n  🎯 TOP DESTINATION IPs")
        for ip, count in profile.top_dst_ips[:5]:
            print(f"     {ip:<20} {count:>6} packets")

        print(f"\n  🔍 DNS ANALYSIS")
        print(f"     Unique Queries  : {profile.unique_dns_queries}")
        print(f"     Query Rate      : {profile.dns_query_rate:.2f}/s")
        for domain, count in profile.top_queried_domains[:5]:
            print(f"     {domain:<40} {count:>4} queries")

        print(f"\n  ⚠  THREAT INDICATORS")
        print(f"     Suspicious Pkt% : {profile.suspicious_packet_ratio*100:.2f}%")
        print(f"     SYN-only Pkts   : {profile.syn_only_packets}")
        print(f"     RST Packets     : {profile.rst_packets}")
        print(f"     RST/TCP Ratio   : {profile.connection_resets_ratio*100:.2f}%")
        print(f"     TTL Anomalies   : {profile.ttl_anomalies}")
        print(f"     Suspicious IPs  : {profile.unique_suspicious_ips}")
        print(f"\n{divider}\n")
