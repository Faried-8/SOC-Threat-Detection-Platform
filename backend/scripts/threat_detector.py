"""
==============================================================================
Network Traffic Analysis & Threat Detection System
Module: Threat Detector
Author: SOC Analysis Framework
Version: 2.0.0
==============================================================================

Description:
    Multi-signature, behavioral threat detection engine.
    Implements rule-based, threshold-based, and behavioral analysis
    detection logic against parsed packet streams.

    MITRE ATT&CK Mappings are included per detection rule.

Detection Categories:
    - Port Scanning (T1046)
    - DNS Tunneling (T1071.004)
    - C2 Beaconing (T1071.001, T1571)
    - Brute Force (T1110)
    - ICMP Flood (T1499)
    - Suspicious HTTP (T1190, T1059)
    - Data Exfiltration Indicators (T1048)
    - Credential Stuffing Indicators (T1110.004)
==============================================================================
"""

import logging
import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, field, asdict
from scripts.packet_parser import ParsedPacket

logger = logging.getLogger("ThreatDetector")


# ─── Alert Data Model ─────────────────────────────────────────────────────────
@dataclass
class ThreatAlert:
    """Structured threat alert produced by the detection engine."""
    alert_id: str
    timestamp: str
    severity: str                  # INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL
    category: str                  # e.g., PORT_SCAN, DNS_TUNNEL, BEACONING
    title: str
    description: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    mitre_technique: str
    mitre_tactic: str
    evidence: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    packet_ids: List[int] = field(default_factory=list)
    analyst_notes: str = ""
    false_positive_likelihood: str = "LOW"   # LOW | MEDIUM | HIGH
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Detection Configuration ──────────────────────────────────────────────────
class DetectionConfig:
    """Centralized detection thresholds and rules configuration."""

    # Port Scan Detection
    PORT_SCAN_THRESHOLD = 15           # Unique ports from one IP within window
    PORT_SCAN_TIME_WINDOW_SECONDS = 60
    PORT_SCAN_SYN_THRESHOLD = 20       # Pure SYN packets

    # DNS Anomaly Detection
    DNS_REQUEST_THRESHOLD = 50         # DNS queries per IP per minute
    DNS_LONG_DOMAIN_THRESHOLD = 50     # Characters in domain name
    DNS_SUBDOMAIN_ENTROPY_THRESHOLD = 3.5  # Shannon entropy of subdomain

    # Beaconing Detection
    BEACONING_MIN_CONNECTIONS = 10     # Min repeated connections
    BEACONING_TIME_WINDOW = 300        # Seconds
    BEACONING_REGULARITY_THRESHOLD = 0.8  # 0.0–1.0 interval regularity score

    # Brute Force Detection
    BRUTE_FORCE_THRESHOLD = 10         # Failed attempts per IP
    BRUTE_FORCE_PORTS = {22, 23, 21, 25, 110, 143, 3389, 5900, 1433, 3306, 5432}
    BRUTE_FORCE_TIME_WINDOW = 60

    # ICMP Flood
    ICMP_FLOOD_THRESHOLD = 100         # ICMP packets per IP per minute

    # HTTP Anomalies
    HTTP_ERROR_THRESHOLD = 20          # 4xx/5xx responses per IP
    HTTP_SCAN_THRESHOLD = 30           # Rapid distinct URI requests

    # Data Exfiltration
    EXFIL_BYTES_THRESHOLD = 5_000_000  # 5MB outbound in session
    EXFIL_DNS_THRESHOLD = 500          # Outbound DNS bytes

    # Known malicious ports (common C2, malware)
    SUSPICIOUS_PORTS = {
        4444, 4445, 1234, 31337, 6666, 6667, 6668, 1337,
        8888, 9999, 2222, 65000, 65535, 12345, 54321, 1080
    }

    # Known bad user agents (partial match)
    MALICIOUS_USER_AGENTS = [
        "sqlmap", "nikto", "nmap script", "masscan", "hydra",
        "metasploit", "havoc", "cobalt", "meterpreter",
        "zgrab", "nuclei", "dirb", "gobuster", "wfuzz"
    ]


# ─── Main Detection Engine ────────────────────────────────────────────────────
class ThreatDetector:
    """
    Behavioral and signature-based threat detection engine.

    Processes parsed packet streams and generates structured ThreatAlerts
    for consumption by the AlertGenerator and ReportGenerator.
    """

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()
        self.alerts: List[ThreatAlert] = []
        self._alert_counter = 0
        logger.info("[DETECTOR] ThreatDetector initialized with %s config",
                    type(self.config).__name__)

    def analyze(self, packets: List[ParsedPacket]) -> List[ThreatAlert]:
        """
        Run all detection modules against the parsed packet list.
        Returns a deduplicated, severity-sorted alert list.
        """
        logger.info(f"[ANALYZE] Running detection engine on {len(packets)} packets...")

        # Pre-index packets for efficient lookup
        self._index_packets(packets)

        # ── Run Detection Modules ──────────────────────────────────────────────
        self._detect_port_scans()
        self._detect_dns_anomalies()
        self._detect_http_anomalies()
        self._detect_beaconing()
        self._detect_brute_force()
        self._detect_icmp_flood()
        self._detect_suspicious_ports()
        self._detect_exfiltration_indicators()
        self._detect_malicious_user_agents()

        # Sort alerts by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        self.alerts.sort(key=lambda a: severity_order.get(a.severity, 99))

        logger.info(f"[ANALYZE] Detection complete. Generated {len(self.alerts)} alerts.")
        return self.alerts

    def _index_packets(self, packets: List[ParsedPacket]):
        """Build lookup indices for O(1) detection lookups."""
        self.packets = packets

        # IP-based indices
        self.src_to_packets: Dict[str, List[ParsedPacket]] = defaultdict(list)
        self.dst_to_packets: Dict[str, List[ParsedPacket]] = defaultdict(list)
        self.ip_pair_packets: Dict[Tuple, List[ParsedPacket]] = defaultdict(list)

        # Protocol indices
        self.dns_packets: List[ParsedPacket] = []
        self.http_packets: List[ParsedPacket] = []
        self.icmp_packets: List[ParsedPacket] = []
        self.tcp_packets: List[ParsedPacket] = []

        for pkt in packets:
            self.src_to_packets[pkt.src_ip].append(pkt)
            self.dst_to_packets[pkt.dst_ip].append(pkt)
            self.ip_pair_packets[(pkt.src_ip, pkt.dst_ip)].append(pkt)

            if pkt.protocol == "DNS":
                self.dns_packets.append(pkt)
            elif pkt.protocol in ("HTTP",):
                self.http_packets.append(pkt)
            elif pkt.protocol == "ICMP":
                self.icmp_packets.append(pkt)
            elif pkt.protocol == "TCP":
                self.tcp_packets.append(pkt)

        logger.debug(f"[INDEX] Indexed {len(packets)} packets across "
                     f"{len(self.src_to_packets)} source IPs")

    # ─── Detection Module: Port Scanning ─────────────────────────────────────
    def _detect_port_scans(self):
        """
        Detect port scanning behavior.

        Logic:
          - Count unique destination ports per source IP (within time window)
          - Flag source IPs exceeding PORT_SCAN_THRESHOLD unique ports
          - Differentiate SYN scans from full connection attempts
          - Detect sequential port probing patterns

        MITRE: T1046 - Network Service Scanning
        """
        logger.info("[DETECT] Running port scan detection...")

        for src_ip, pkts in self.src_to_packets.items():
            tcp_pkts = [p for p in pkts if p.protocol == "TCP"]
            if len(tcp_pkts) < self.config.PORT_SCAN_THRESHOLD:
                continue

            # Collect unique destination IPs and ports
            dst_ports_per_ip: Dict[str, set] = defaultdict(set)
            syn_count = 0

            for pkt in tcp_pkts:
                if pkt.dst_port:
                    dst_ports_per_ip[pkt.dst_ip].add(pkt.dst_port)
                if pkt.flags and "SYN" in pkt.flags and "ACK" not in pkt.flags:
                    syn_count += 1

            # Check horizontal scan (many ports on one host)
            for dst_ip, ports in dst_ports_per_ip.items():
                if len(ports) >= self.config.PORT_SCAN_THRESHOLD:
                    severity = "HIGH" if syn_count > self.config.PORT_SCAN_SYN_THRESHOLD else "MEDIUM"
                    scan_type = "SYN Scan" if syn_count > self.config.PORT_SCAN_SYN_THRESHOLD else "TCP Connect Scan"

                    self._create_alert(
                        severity=severity,
                        category="PORT_SCAN",
                        title=f"{scan_type} Detected",
                        description=(
                            f"Source IP {src_ip} probed {len(ports)} unique ports "
                            f"on {dst_ip}. {syn_count} pure SYN packets detected. "
                            f"This pattern is consistent with automated network reconnaissance."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=None,
                        dst_port=None,
                        protocol="TCP",
                        mitre_technique="T1046",
                        mitre_tactic="Discovery",
                        evidence=[
                            f"Unique ports probed: {sorted(list(ports))[:20]}",
                            f"Total SYN packets: {syn_count}",
                            f"Total TCP packets from source: {len(tcp_pkts)}"
                        ],
                        iocs=[src_ip],
                        recommended_action=(
                            "Block source IP at perimeter firewall. "
                            "Correlate with threat intelligence feeds. "
                            "Investigate if scan reached internal assets."
                        ),
                        false_positive_likelihood="LOW"
                    )

    # ─── Detection Module: DNS Anomalies ─────────────────────────────────────
    def _detect_dns_anomalies(self):
        """
        Detect DNS-based attack patterns.

        Includes:
          - Excessive query volume (possible C2 polling)
          - Long domain names (DNS tunneling)
          - High-entropy subdomains (DGA / DNS exfiltration)
          - Repeated NXDOMAIN responses (DGA enumeration)

        MITRE: T1071.004 - Application Layer Protocol: DNS
        """
        logger.info("[DETECT] Running DNS anomaly detection...")

        dns_by_src: Dict[str, List[ParsedPacket]] = defaultdict(list)
        for pkt in self.dns_packets:
            dns_by_src[pkt.src_ip].append(pkt)

        for src_ip, pkts in dns_by_src.items():
            # Volume-based detection
            if len(pkts) >= self.config.DNS_REQUEST_THRESHOLD:
                queries = [p.dns_query for p in pkts if p.dns_query]
                self._create_alert(
                    severity="MEDIUM",
                    category="DNS_ANOMALY",
                    title="Excessive DNS Query Volume",
                    description=(
                        f"Source IP {src_ip} generated {len(pkts)} DNS queries. "
                        f"Threshold: {self.config.DNS_REQUEST_THRESHOLD}. "
                        f"High DNS volume may indicate C2 polling, fast-flux DNS, or DGA malware activity."
                    ),
                    src_ip=src_ip,
                    dst_ip="DNS_SERVER",
                    src_port=None,
                    dst_port=53,
                    protocol="DNS",
                    mitre_technique="T1071.004",
                    mitre_tactic="Command and Control",
                    evidence=[
                        f"Total DNS queries: {len(pkts)}",
                        f"Sample queries: {queries[:10]}"
                    ],
                    iocs=[src_ip] + queries[:5],
                    recommended_action="Review DNS logs. Block or sinkhole suspicious domains.",
                    false_positive_likelihood="MEDIUM"
                )

            # Long domain / tunneling detection
            long_domains = []
            for pkt in pkts:
                if pkt.dns_query and len(pkt.dns_query) > self.config.DNS_LONG_DOMAIN_THRESHOLD:
                    entropy = self._calculate_entropy(pkt.dns_query)
                    if entropy > self.config.DNS_SUBDOMAIN_ENTROPY_THRESHOLD:
                        long_domains.append((pkt.dns_query, entropy))

            if len(long_domains) >= 5:
                self._create_alert(
                    severity="HIGH",
                    category="DNS_TUNNEL",
                    title="Possible DNS Tunneling Detected",
                    description=(
                        f"Source IP {src_ip} queried {len(long_domains)} high-entropy, "
                        f"abnormally long domain names. DNS tunneling tools (like iodine, dnscat2) "
                        f"encode data within DNS queries to bypass firewalls."
                    ),
                    src_ip=src_ip,
                    dst_ip="DNS_SERVER",
                    src_port=None,
                    dst_port=53,
                    protocol="DNS",
                    mitre_technique="T1071.004",
                    mitre_tactic="Command and Control / Exfiltration",
                    evidence=[f"Domain: {d[0]} (entropy: {d[1]:.2f})" for d in long_domains[:5]],
                    iocs=[src_ip] + [d[0] for d in long_domains[:10]],
                    recommended_action=(
                        "Block DNS queries to identified domains. "
                        "Enable DNS response policy zone (RPZ). "
                        "Isolate affected host and conduct memory forensics."
                    ),
                    false_positive_likelihood="LOW"
                )

    # ─── Detection Module: HTTP Anomalies ────────────────────────────────────
    def _detect_http_anomalies(self):
        """
        Detect malicious HTTP patterns.

        Includes:
          - Malicious user agents (scanners, exploit frameworks)
          - Web application attack URIs (SQLi, LFI, RFI, webshells)
          - High 4xx/5xx error rates (fuzzing/scanning)
          - Suspicious POST activity (possible webshell interaction)
          - Large outbound HTTP bodies (possible exfiltration)

        MITRE: T1190 - Exploit Public-Facing Application
               T1059 - Command and Scripting Interpreter
        """
        logger.info("[DETECT] Running HTTP anomaly detection...")

        http_by_src: Dict[str, List[ParsedPacket]] = defaultdict(list)
        for pkt in self.http_packets:
            http_by_src[pkt.src_ip].append(pkt)

        for src_ip, pkts in http_by_src.items():
            # Malicious user agent detection
            for pkt in pkts:
                if pkt.http_user_agent:
                    ua_lower = pkt.http_user_agent.lower()
                    for mal_ua in self.config.MALICIOUS_USER_AGENTS:
                        if mal_ua.lower() in ua_lower:
                            self._create_alert(
                                severity="HIGH",
                                category="MALICIOUS_UA",
                                title=f"Malicious User-Agent Detected: {mal_ua}",
                                description=(
                                    f"Source IP {src_ip} sent HTTP request with known malicious "
                                    f"user-agent '{pkt.http_user_agent}'. This tool is commonly "
                                    f"associated with exploitation or automated scanning activity."
                                ),
                                src_ip=src_ip,
                                dst_ip=pkt.dst_ip,
                                src_port=pkt.src_port,
                                dst_port=pkt.dst_port,
                                protocol="HTTP",
                                mitre_technique="T1190",
                                mitre_tactic="Initial Access",
                                evidence=[
                                    f"User-Agent: {pkt.http_user_agent}",
                                    f"Target URI: {pkt.http_uri}",
                                    f"Host: {pkt.http_host}"
                                ],
                                iocs=[src_ip, pkt.http_user_agent or "", pkt.http_host or ""],
                                recommended_action=(
                                    "Block source IP. Review web server logs for exploitation success. "
                                    "Check for webshell artifacts on target server."
                                ),
                                false_positive_likelihood="LOW"
                            )
                            break  # One alert per packet

            # Rapid URI scanning
            unique_uris = set(p.http_uri for p in pkts if p.http_uri)
            if len(unique_uris) >= self.config.HTTP_SCAN_THRESHOLD:
                self._create_alert(
                    severity="HIGH",
                    category="HTTP_SCAN",
                    title="Web Application Scanning Detected",
                    description=(
                        f"Source IP {src_ip} requested {len(unique_uris)} unique URIs. "
                        f"This pattern is consistent with directory brute forcing or "
                        f"web application vulnerability scanning."
                    ),
                    src_ip=src_ip,
                    dst_ip=pkts[0].dst_ip if pkts else "UNKNOWN",
                    src_port=None,
                    dst_port=80,
                    protocol="HTTP",
                    mitre_technique="T1595.003",
                    mitre_tactic="Reconnaissance",
                    evidence=[
                        f"Unique URIs requested: {len(unique_uris)}",
                        f"Sample URIs: {list(unique_uris)[:10]}"
                    ],
                    iocs=[src_ip] + list(unique_uris)[:10],
                    recommended_action="Rate-limit or block source IP. Enable WAF rules.",
                    false_positive_likelihood="LOW"
                )

    # ─── Detection Module: Beaconing ─────────────────────────────────────────
    def _detect_beaconing(self):
        """
        Detect C2 beaconing behavior through interval regularity analysis.

        Beaconing detection logic:
          - Identify IP pairs with repeated connections
          - Calculate inter-connection time intervals
          - Measure interval standard deviation (low StdDev = regular = beaconing)
          - Flag pairs with high connection regularity scores

        MITRE: T1071.001 - Application Layer Protocol: Web Protocols
               T1571 - Non-Standard Port
        """
        logger.info("[DETECT] Running beaconing detection...")
        import statistics

        for (src_ip, dst_ip), pkts in self.ip_pair_packets.items():
            if len(pkts) < self.config.BEACONING_MIN_CONNECTIONS:
                continue

            try:
                # Parse timestamps and compute intervals
                timestamps = []
                for pkt in pkts:
                    try:
                        ts = datetime.fromisoformat(pkt.timestamp.replace("Z", ""))
                        timestamps.append(ts)
                    except Exception:
                        continue

                if len(timestamps) < self.config.BEACONING_MIN_CONNECTIONS:
                    continue

                timestamps.sort()
                intervals = [
                    (timestamps[i+1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps)-1)
                ]

                if len(intervals) < 5:
                    continue

                mean_interval = statistics.mean(intervals)
                std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
                coefficient_of_variation = (std_dev / mean_interval) if mean_interval > 0 else 1

                # Low CoV = highly regular = possible beaconing
                regularity_score = 1.0 - min(coefficient_of_variation, 1.0)

                if regularity_score >= self.config.BEACONING_REGULARITY_THRESHOLD:
                    dst_port = pkts[0].dst_port
                    severity = "CRITICAL" if regularity_score > 0.95 else "HIGH"

                    self._create_alert(
                        severity=severity,
                        category="BEACONING",
                        title="C2 Beaconing Behavior Detected",
                        description=(
                            f"Host {src_ip} exhibits highly regular outbound connection patterns "
                            f"to {dst_ip}:{dst_port}. Regularity score: {regularity_score:.2f}/1.00. "
                            f"Mean interval: {mean_interval:.1f}s ± {std_dev:.1f}s. "
                            f"This is consistent with malware C2 callback behavior."
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=None,
                        dst_port=dst_port,
                        protocol=pkts[0].protocol,
                        mitre_technique="T1071.001",
                        mitre_tactic="Command and Control",
                        evidence=[
                            f"Connection count: {len(pkts)}",
                            f"Mean interval: {mean_interval:.2f}s",
                            f"Std deviation: {std_dev:.2f}s",
                            f"Regularity score: {regularity_score:.2f}",
                            f"Destination port: {dst_port}"
                        ],
                        iocs=[src_ip, dst_ip, str(dst_port)],
                        recommended_action=(
                            "Isolate host immediately. Capture memory dump. "
                            "Block outbound connections to destination IP. "
                            "Submit destination IP to threat intelligence platforms."
                        ),
                        false_positive_likelihood="LOW"
                    )
            except Exception as e:
                logger.debug(f"[BEACONING] Analysis error for {src_ip}->{dst_ip}: {e}")

    # ─── Detection Module: Brute Force ───────────────────────────────────────
    def _detect_brute_force(self):
        """
        Detect credential brute force attempts.

        Logic:
          - Monitor connection attempts to authentication ports
          - Count unique connection attempts per source IP per time window
          - Flag sources exceeding brute force threshold
          - Track targeted services for context

        MITRE: T1110 - Brute Force
               T1110.001 - Password Guessing
               T1110.003 - Password Spraying
        """
        logger.info("[DETECT] Running brute force detection...")

        for src_ip, pkts in self.src_to_packets.items():
            auth_attempts: Dict[int, int] = defaultdict(int)

            for pkt in pkts:
                if pkt.dst_port in self.config.BRUTE_FORCE_PORTS:
                    auth_attempts[pkt.dst_port] += 1

            for port, count in auth_attempts.items():
                if count >= self.config.BRUTE_FORCE_THRESHOLD:
                    service_map = {
                        22: "SSH", 23: "Telnet", 21: "FTP", 25: "SMTP",
                        110: "POP3", 143: "IMAP", 3389: "RDP", 5900: "VNC",
                        1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL"
                    }
                    service = service_map.get(port, f"Port/{port}")

                    self._create_alert(
                        severity="HIGH",
                        category="BRUTE_FORCE",
                        title=f"{service} Brute Force Attack Detected",
                        description=(
                            f"Source IP {src_ip} made {count} connection attempts to "
                            f"{service} (port {port}). This volume significantly exceeds "
                            f"normal authentication patterns and indicates automated "
                            f"credential brute force activity."
                        ),
                        src_ip=src_ip,
                        dst_ip="MULTIPLE",
                        src_port=None,
                        dst_port=port,
                        protocol="TCP",
                        mitre_technique="T1110",
                        mitre_tactic="Credential Access",
                        evidence=[
                            f"Target service: {service} (port {port})",
                            f"Connection attempts: {count}",
                            f"Threshold: {self.config.BRUTE_FORCE_THRESHOLD}"
                        ],
                        iocs=[src_ip],
                        recommended_action=(
                            f"Block {src_ip} at firewall. Enable account lockout policy. "
                            f"Audit {service} authentication logs for successful logins. "
                            "Consider deploying fail2ban or similar rate-limiting."
                        ),
                        false_positive_likelihood="LOW"
                    )

    # ─── Detection Module: ICMP Flood ────────────────────────────────────────
    def _detect_icmp_flood(self):
        """
        Detect ICMP-based attacks and reconnaissance.

        MITRE: T1499 - Endpoint Denial of Service
               T1018 - Remote System Discovery (ping sweep)
        """
        logger.info("[DETECT] Running ICMP flood detection...")

        icmp_by_src: Dict[str, List[ParsedPacket]] = defaultdict(list)
        for pkt in self.icmp_packets:
            icmp_by_src[pkt.src_ip].append(pkt)

        for src_ip, pkts in icmp_by_src.items():
            if len(pkts) >= self.config.ICMP_FLOOD_THRESHOLD:
                unique_dsts = set(p.dst_ip for p in pkts)
                is_sweep = len(unique_dsts) > 10

                category = "ICMP_SWEEP" if is_sweep else "ICMP_FLOOD"
                title = "ICMP Ping Sweep (Network Discovery)" if is_sweep else "ICMP Flood Attack"
                mitre = "T1018" if is_sweep else "T1499"
                tactic = "Discovery" if is_sweep else "Impact"

                self._create_alert(
                    severity="MEDIUM",
                    category=category,
                    title=title,
                    description=(
                        f"Source IP {src_ip} sent {len(pkts)} ICMP packets to "
                        f"{len(unique_dsts)} unique destinations. "
                        f"{'Ping sweep pattern detected.' if is_sweep else 'Flood pattern detected.'}"
                    ),
                    src_ip=src_ip,
                    dst_ip=f"{len(unique_dsts)} hosts",
                    src_port=None,
                    dst_port=None,
                    protocol="ICMP",
                    mitre_technique=mitre,
                    mitre_tactic=tactic,
                    evidence=[
                        f"ICMP packets: {len(pkts)}",
                        f"Unique destinations: {len(unique_dsts)}"
                    ],
                    iocs=[src_ip],
                    recommended_action="Block ICMP from external sources. Rate-limit internal ICMP.",
                    false_positive_likelihood="MEDIUM"
                )

    # ─── Detection Module: Suspicious Ports ──────────────────────────────────
    def _detect_suspicious_ports(self):
        """
        Detect traffic on known malware/C2 ports.
        MITRE: T1571 - Non-Standard Port
        """
        logger.info("[DETECT] Running suspicious port detection...")

        for pkt in self.packets:
            if pkt.dst_port in self.config.SUSPICIOUS_PORTS:
                self._create_alert(
                    severity="MEDIUM",
                    category="SUSPICIOUS_PORT",
                    title=f"Traffic on Known Malware Port {pkt.dst_port}",
                    description=(
                        f"Connection from {pkt.src_ip} to {pkt.dst_ip}:{pkt.dst_port}. "
                        f"Port {pkt.dst_port} is associated with common malware, RATs, or C2 frameworks."
                    ),
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    mitre_technique="T1571",
                    mitre_tactic="Command and Control",
                    evidence=[f"Destination port: {pkt.dst_port}"],
                    iocs=[pkt.src_ip, pkt.dst_ip, str(pkt.dst_port)],
                    recommended_action="Block port at perimeter. Investigate source host.",
                    false_positive_likelihood="MEDIUM"
                )

    # ─── Detection Module: Exfiltration Indicators ───────────────────────────
    def _detect_exfiltration_indicators(self):
        """
        Detect potential data exfiltration patterns.
        MITRE: T1048 - Exfiltration Over Alternative Protocol
        """
        logger.info("[DETECT] Running exfiltration indicator detection...")

        bytes_by_src: Dict[str, int] = defaultdict(int)
        for pkt in self.packets:
            bytes_by_src[pkt.src_ip] += pkt.length

        for src_ip, total_bytes in bytes_by_src.items():
            if total_bytes >= self.config.EXFIL_BYTES_THRESHOLD:
                self._create_alert(
                    severity="HIGH",
                    category="EXFILTRATION",
                    title="High-Volume Outbound Data Transfer",
                    description=(
                        f"Source IP {src_ip} transmitted {total_bytes:,} bytes outbound. "
                        f"Threshold: {self.config.EXFIL_BYTES_THRESHOLD:,} bytes. "
                        f"Large outbound transfers may indicate data exfiltration activity."
                    ),
                    src_ip=src_ip,
                    dst_ip="MULTIPLE",
                    src_port=None,
                    dst_port=None,
                    protocol="MIXED",
                    mitre_technique="T1048",
                    mitre_tactic="Exfiltration",
                    evidence=[f"Total bytes: {total_bytes:,}"],
                    iocs=[src_ip],
                    recommended_action=(
                        "Investigate outbound destinations. Review DLP logs. "
                        "Isolate host if exfiltration is confirmed."
                    ),
                    false_positive_likelihood="MEDIUM"
                )

    # ─── Detection Module: Malicious User Agents ─────────────────────────────
    def _detect_malicious_user_agents(self):
        """Already handled inline in HTTP detection — placeholder for extension."""
        pass

    # ─── Utility Methods ─────────────────────────────────────────────────────
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string (used for DGA/tunneling detection)."""
        import math
        if not text:
            return 0.0
        freq = Counter(text.lower())
        total = len(text)
        return -sum((c/total) * math.log2(c/total) for c in freq.values())

    def _create_alert(self, **kwargs) -> ThreatAlert:
        """Factory method for creating standardized ThreatAlert objects."""
        self._alert_counter += 1
        alert_id = f"ALERT-{datetime.utcnow().strftime('%Y%m%d')}-{self._alert_counter:04d}"
        alert = ThreatAlert(
            alert_id=alert_id,
            timestamp=datetime.utcnow().isoformat(),
            **kwargs
        )
        self.alerts.append(alert)
        logger.info(
            f"[ALERT] {alert.severity} | {alert.category} | {alert.title} | "
            f"SRC: {alert.src_ip} → DST: {alert.dst_ip}"
        )
        return alert

    def get_summary(self) -> Dict[str, Any]:
        """Generate detection summary statistics."""
        severity_counts = Counter(a.severity for a in self.alerts)
        category_counts = Counter(a.category for a in self.alerts)
        return {
            "total_alerts": len(self.alerts),
            "by_severity": dict(severity_counts),
            "by_category": dict(category_counts),
            "critical_alerts": [a.to_dict() for a in self.alerts if a.severity == "CRITICAL"],
            "top_src_ips": Counter(a.src_ip for a in self.alerts).most_common(10),
        }

    def export_alerts_json(self, output_dir: str = "outputs") -> str:
        """Export all alerts to JSON."""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "threat_alerts.json")
        output = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "total_alerts": len(self.alerts),
                "engine_version": "2.0.0"
            },
            "summary": self.get_summary(),
            "alerts": [a.to_dict() for a in self.alerts]
        }
        with open(path, "w") as f:
            json.dump(output, f, indent=2, default=str)
        logger.info(f"[EXPORT] Alerts JSON: {path}")
        return path
