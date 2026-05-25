"""
==============================================================================
Network Traffic Analysis & Threat Detection System
Module: Packet Parser
Author: SOC Analysis Framework
Version: 2.0.0
==============================================================================

Description:
    Core packet parsing engine responsible for reading PCAP files and
    extracting structured packet metadata for downstream analysis.
    Handles multi-protocol parsing with graceful error handling and
    structured logging throughout the pipeline.

Usage:
    from scripts.packet_parser import PacketParser
    parser = PacketParser("pcaps/capture.pcap")
    packets = parser.parse()
==============================================================================
"""

import logging
import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logging.warning("[PARSER] PyShark not available. Install with: pip install pyshark")

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("[PARSER] Scapy not available. Install with: pip install scapy")


# ─── Logging Configuration ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s :: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("PacketParser")


# ─── Data Models ──────────────────────────────────────────────────────────────
@dataclass
class ParsedPacket:
    """Structured representation of a parsed network packet."""
    packet_id: int
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    ttl: Optional[int]
    flags: Optional[str]
    payload_size: int
    raw_payload: Optional[str]
    
    # DNS-specific fields
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None
    dns_response: Optional[str] = None
    
    # HTTP-specific fields
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_status_code: Optional[str] = None
    http_content_type: Optional[str] = None
    
    # ICMP-specific fields
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    
    # Analysis tags
    tags: List[str] = field(default_factory=list)
    is_suspicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize packet to dictionary for JSON/CSV output."""
        return asdict(self)


@dataclass
class ParserStats:
    """Statistics accumulated during PCAP parsing."""
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    dns_packets: int = 0
    http_packets: int = 0
    other_packets: int = 0
    parse_errors: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    total_bytes: int = 0


# ─── Parser Engine ────────────────────────────────────────────────────────────
class PacketParser:
    """
    Enterprise-grade PCAP parser with multi-protocol support.
    
    Supports Scapy-based parsing with optional PyShark fallback.
    Extracts structured metadata from TCP, UDP, DNS, HTTP, and ICMP traffic.
    """

    # Known malicious/suspicious user agents
    SUSPICIOUS_USER_AGENTS = [
        "sqlmap", "nikto", "nmap", "masscan", "hydra", "medusa",
        "curl/7.38", "python-requests/2.1", "go-http-client/1.1",
        "zgrab", "nuclei", "dirbuster", "gobuster", "wfuzz",
        "burpsuite", "havoc", "cobalt strike", "meterpreter",
        "wget/", "libwww-perl"
    ]

    # Suspicious HTTP URI patterns
    SUSPICIOUS_URI_PATTERNS = [
        "/admin", "/wp-login", "/phpmyadmin", "/.env", "/config",
        "/shell", "/cmd", "/exec", "/upload", "/../", "%2e%2e",
        "union+select", "1=1", "or+1=1", "<script>", "eval(",
        "base64_decode", "/etc/passwd", "/proc/self"
    ]

    def __init__(self, pcap_path: str, output_dir: str = "outputs"):
        self.pcap_path = pcap_path
        self.output_dir = output_dir
        self.packets: List[ParsedPacket] = []
        self.stats = ParserStats()
        self._src_ips = set()
        self._dst_ips = set()
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"[INIT] PacketParser initialized | Target: {pcap_path}")

    def parse(self) -> List[ParsedPacket]:
        """
        Main parsing entry point.
        Attempts Scapy parsing first, falls back to PyShark if needed.
        """
        if not os.path.exists(self.pcap_path):
            raise FileNotFoundError(f"PCAP not found: {self.pcap_path}")

        logger.info(f"[PARSE] Starting PCAP ingestion: {self.pcap_path}")
        self.stats.start_time = datetime.utcnow().isoformat()

        if SCAPY_AVAILABLE:
            self._parse_with_scapy()
        elif PYSHARK_AVAILABLE:
            logger.warning("[PARSE] Scapy unavailable — falling back to PyShark")
            self._parse_with_pyshark()
        else:
            raise RuntimeError("No packet parsing library available. Install scapy or pyshark.")

        self.stats.end_time = datetime.utcnow().isoformat()
        self.stats.unique_src_ips = len(self._src_ips)
        self.stats.unique_dst_ips = len(self._dst_ips)

        logger.info(
            f"[COMPLETE] Parsed {self.stats.total_packets} packets "
            f"({self.stats.parse_errors} errors) | "
            f"Duration window: {self.stats.start_time} → {self.stats.end_time}"
        )
        return self.packets

    # ─── Scapy Parsing ────────────────────────────────────────────────────────
    def _parse_with_scapy(self):
        """Parse PCAP using Scapy for high-performance extraction."""
        logger.info("[SCAPY] Loading PCAP with Scapy engine...")
        try:
            raw_packets = rdpcap(self.pcap_path)
        except Exception as e:
            logger.error(f"[SCAPY] Failed to read PCAP: {e}")
            raise

        logger.info(f"[SCAPY] Loaded {len(raw_packets)} raw packets")

        for idx, pkt in enumerate(raw_packets):
            try:
                parsed = self._extract_scapy_packet(idx, pkt)
                if parsed:
                    self.packets.append(parsed)
                    self.stats.total_packets += 1
                    self.stats.total_bytes += parsed.length
                    self._src_ips.add(parsed.src_ip)
                    self._dst_ips.add(parsed.dst_ip)
                    self._update_protocol_stats(parsed.protocol)
            except Exception as e:
                self.stats.parse_errors += 1
                logger.debug(f"[SCAPY] Packet {idx} parse error: {e}")

    def _extract_scapy_packet(self, idx: int, pkt) -> Optional[ParsedPacket]:
        """Extract structured fields from a Scapy packet object."""
        if not pkt.haslayer(IP):
            return None  # Skip non-IP frames (ARP, etc.)

        ip = pkt[IP]
        timestamp = datetime.utcfromtimestamp(float(pkt.time)).isoformat() if hasattr(pkt, 'time') else datetime.utcnow().isoformat()

        # Build base packet structure
        parsed = ParsedPacket(
            packet_id=idx,
            timestamp=timestamp,
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            src_port=None,
            dst_port=None,
            protocol="OTHER",
            length=len(pkt),
            ttl=ip.ttl,
            flags=None,
            payload_size=len(pkt.payload) if pkt.payload else 0,
            raw_payload=None,
        )

        # ── TCP Layer ──────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            parsed.protocol = "TCP"
            parsed.src_port = int(tcp.sport)
            parsed.dst_port = int(tcp.dport)
            parsed.flags = self._decode_tcp_flags(tcp.flags)
            self.stats.tcp_packets += 1

            # Extract HTTP if present
            if pkt.haslayer(Raw):
                raw = pkt[Raw].load
                self._extract_http_fields(parsed, raw)

        # ── UDP Layer ──────────────────────────────────────────────────────────
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            parsed.protocol = "UDP"
            parsed.src_port = int(udp.sport)
            parsed.dst_port = int(udp.dport)
            self.stats.udp_packets += 1

            # Extract DNS if present
            if pkt.haslayer(DNS):
                self._extract_dns_fields(parsed, pkt[DNS])

        # ── ICMP Layer ─────────────────────────────────────────────────────────
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            parsed.protocol = "ICMP"
            parsed.icmp_type = int(icmp.type)
            parsed.icmp_code = int(icmp.code)
            self.stats.icmp_packets += 1

        # Tag suspicious characteristics
        self._apply_initial_tags(parsed)
        return parsed

    def _decode_tcp_flags(self, flags) -> str:
        """Decode Scapy TCP flags into human-readable string."""
        flag_map = {
            "F": "FIN", "S": "SYN", "R": "RST",
            "P": "PSH", "A": "ACK", "U": "URG",
            "E": "ECE", "C": "CWR"
        }
        try:
            flag_str = str(flags)
            return " | ".join([flag_map.get(c, c) for c in flag_str if c in flag_map])
        except Exception:
            return str(flags)

    def _extract_dns_fields(self, parsed: ParsedPacket, dns_layer):
        """Extract DNS query/response metadata."""
        parsed.protocol = "DNS"
        self.stats.dns_packets += 1
        try:
            if dns_layer.qd:
                parsed.dns_query = str(dns_layer.qd.qname.decode() if isinstance(dns_layer.qd.qname, bytes) else dns_layer.qd.qname)
                qtype_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
                parsed.dns_type = qtype_map.get(dns_layer.qd.qtype, str(dns_layer.qd.qtype))
            if dns_layer.an:
                parsed.dns_response = str(dns_layer.an)
        except Exception as e:
            logger.debug(f"[DNS] Extraction error: {e}")

    def _extract_http_fields(self, parsed: ParsedPacket, raw: bytes):
        """Extract HTTP request/response metadata from raw payload."""
        try:
            decoded = raw.decode("utf-8", errors="ignore")
            lines = decoded.split("\r\n")
            if not lines:
                return

            first_line = lines[0]
            # HTTP Request
            if any(first_line.startswith(m) for m in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]):
                parts = first_line.split(" ")
                if len(parts) >= 2:
                    parsed.http_method = parts[0]
                    parsed.http_uri = parts[1]
                    parsed.protocol = "HTTP"
                    self.stats.http_packets += 1

                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        parsed.http_host = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("user-agent:"):
                        parsed.http_user_agent = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("content-type:"):
                        parsed.http_content_type = line.split(":", 1)[1].strip()

            # HTTP Response
            elif first_line.startswith("HTTP/"):
                parts = first_line.split(" ")
                if len(parts) >= 2:
                    parsed.http_status_code = parts[1]
                    parsed.protocol = "HTTP"

        except Exception as e:
            logger.debug(f"[HTTP] Extraction error: {e}")

    def _apply_initial_tags(self, parsed: ParsedPacket):
        """Apply preliminary suspicion tags based on protocol anomalies."""
        # Suspicious user agent
        if parsed.http_user_agent:
            ua_lower = parsed.http_user_agent.lower()
            for suspicious_ua in self.SUSPICIOUS_USER_AGENTS:
                if suspicious_ua.lower() in ua_lower:
                    parsed.tags.append(f"SUSPICIOUS_UA:{suspicious_ua}")
                    parsed.is_suspicious = True

        # Suspicious URI
        if parsed.http_uri:
            uri_lower = parsed.http_uri.lower()
            for pattern in self.SUSPICIOUS_URI_PATTERNS:
                if pattern.lower() in uri_lower:
                    parsed.tags.append(f"SUSPICIOUS_URI:{pattern}")
                    parsed.is_suspicious = True

        # Long DNS queries (potential tunneling)
        if parsed.dns_query and len(parsed.dns_query) > 50:
            parsed.tags.append("LONG_DNS_QUERY")
            parsed.is_suspicious = True

        # High TTL anomalies (may indicate spoofing)
        if parsed.ttl and parsed.ttl > 250:
            parsed.tags.append("ANOMALOUS_TTL")

        # SYN-only (possible port scan)
        if parsed.flags == "SYN":
            parsed.tags.append("TCP_SYN_ONLY")

        # RST flood indicator
        if parsed.flags and "RST" in parsed.flags:
            parsed.tags.append("TCP_RST")

    def _parse_with_pyshark(self):
        """Fallback parser using PyShark (TShark-based)."""
        logger.info("[PYSHARK] Loading PCAP with PyShark engine...")
        try:
            cap = pyshark.FileCapture(self.pcap_path)
            for idx, pkt in enumerate(cap):
                try:
                    parsed = self._extract_pyshark_packet(idx, pkt)
                    if parsed:
                        self.packets.append(parsed)
                        self.stats.total_packets += 1
                        self.stats.total_bytes += parsed.length
                        self._src_ips.add(parsed.src_ip)
                        self._dst_ips.add(parsed.dst_ip)
                        self._update_protocol_stats(parsed.protocol)
                except Exception as e:
                    self.stats.parse_errors += 1
                    logger.debug(f"[PYSHARK] Packet {idx} error: {e}")
            cap.close()
        except Exception as e:
            logger.error(f"[PYSHARK] Failed: {e}")
            raise

    def _extract_pyshark_packet(self, idx: int, pkt) -> Optional[ParsedPacket]:
        """Extract fields from a PyShark packet object."""
        try:
            src_ip = str(pkt.ip.src) if hasattr(pkt, 'ip') else "0.0.0.0"
            dst_ip = str(pkt.ip.dst) if hasattr(pkt, 'ip') else "0.0.0.0"
            protocol = pkt.highest_layer if hasattr(pkt, 'highest_layer') else "UNKNOWN"
            length = int(pkt.length) if hasattr(pkt, 'length') else 0

            parsed = ParsedPacket(
                packet_id=idx,
                timestamp=str(pkt.sniff_time) if hasattr(pkt, 'sniff_time') else datetime.utcnow().isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=int(pkt[pkt.transport_layer].srcport) if hasattr(pkt, 'transport_layer') and pkt.transport_layer else None,
                dst_port=int(pkt[pkt.transport_layer].dstport) if hasattr(pkt, 'transport_layer') and pkt.transport_layer else None,
                protocol=protocol,
                length=length,
                ttl=int(pkt.ip.ttl) if hasattr(pkt, 'ip') else None,
                flags=None,
                payload_size=0,
                raw_payload=None,
            )
            return parsed
        except Exception:
            return None

    def _update_protocol_stats(self, protocol: str):
        """Increment protocol-specific counters."""
        proto_upper = protocol.upper()
        if proto_upper == "TCP":
            self.stats.tcp_packets += 1
        elif proto_upper == "UDP":
            self.stats.udp_packets += 1
        elif proto_upper == "ICMP":
            self.stats.icmp_packets += 1
        elif proto_upper == "DNS":
            self.stats.dns_packets += 1
        elif proto_upper == "HTTP":
            self.stats.http_packets += 1
        else:
            self.stats.other_packets += 1

    # ─── Export Methods ───────────────────────────────────────────────────────
    def export_json(self, filename: str = "parsed_packets.json") -> str:
        """Export all parsed packets to JSON format."""
        path = os.path.join(self.output_dir, filename)
        output = {
            "metadata": {
                "pcap_file": self.pcap_path,
                "exported_at": datetime.utcnow().isoformat(),
                "parser_version": "2.0.0",
                "stats": asdict(self.stats)
            },
            "packets": [p.to_dict() for p in self.packets]
        }
        with open(path, "w") as f:
            json.dump(output, f, indent=2, default=str)
        logger.info(f"[EXPORT] JSON written: {path}")
        return path

    def export_csv(self, filename: str = "parsed_packets.csv") -> str:
        """Export parsed packets to CSV for spreadsheet analysis."""
        path = os.path.join(self.output_dir, filename)
        if not self.packets:
            logger.warning("[EXPORT] No packets to export.")
            return path
        fieldnames = list(self.packets[0].to_dict().keys())
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for pkt in self.packets:
                writer.writerow(pkt.to_dict())
        logger.info(f"[EXPORT] CSV written: {path}")
        return path

    def get_stats(self) -> Dict[str, Any]:
        """Return parser statistics as a dictionary."""
        return asdict(self.stats)
