"""
==============================================================================
Network Traffic Analysis & Threat Detection System
Module: IOC Extractor
Version: 2.0.0
==============================================================================

Description:
    Extracts and enriches Indicators of Compromise (IOCs) from parsed
    packet data and generated alerts. Deduplicates, categorizes, and
    optionally enriches IOCs via VirusTotal and AbuseIPDB APIs.

IOC Types Extracted:
    - IP Addresses (source and destination)
    - Domain Names (from DNS queries)
    - URLs (from HTTP traffic)
    - User Agents (malicious/suspicious)
    - Port Numbers (suspicious/known-bad)
    - File Hashes (if payload extraction enabled)
    - Protocol Anomalies
==============================================================================
"""

import logging
import json
import csv
import os
import re
import time
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("IOCExtractor")

# Optional: requests for API enrichment
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ─── IOC Data Model ───────────────────────────────────────────────────────────
@dataclass
class IOC:
    """Structured Indicator of Compromise object."""
    ioc_id: str
    ioc_type: str          # IP | DOMAIN | URL | USER_AGENT | PORT | HASH
    value: str
    confidence: str        # HIGH | MEDIUM | LOW
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    first_seen: str
    last_seen: str
    occurrence_count: int
    associated_alerts: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Enrichment fields (populated via API)
    vt_malicious_count: Optional[int] = None
    vt_detection_names: List[str] = field(default_factory=list)
    abuseipdb_score: Optional[int] = None
    abuseipdb_country: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    asn: Optional[str] = None
    is_private: bool = False
    enrichment_status: str = "PENDING"  # PENDING | ENRICHED | FAILED | SKIPPED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── IOC Extractor Engine ─────────────────────────────────────────────────────
class IOCExtractor:
    """
    IOC extraction and enrichment engine.

    Processes parsed packets and threat alerts to produce a deduplicated,
    enriched IOC dataset ready for threat intelligence integration.
    """

    # RFC 1918 private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    # Known legitimate/whitelisted IPs (expand for your environment)
    IP_WHITELIST: Set[str] = {
        "8.8.8.8", "8.8.4.4",         # Google DNS
        "1.1.1.1", "1.0.0.1",         # Cloudflare DNS
        "208.67.222.222",              # OpenDNS
    }

    # Known benign domains (whitelist)
    DOMAIN_WHITELIST: Set[str] = {
        "google.com", "microsoft.com", "windows.com",
        "apple.com", "cloudflare.com", "amazonaws.com",
    }

    # High-confidence malicious port list
    KNOWN_BAD_PORTS = {4444, 4445, 31337, 1337, 6666, 6667, 9999, 12345}

    def __init__(self, vt_api_key: Optional[str] = None,
                 abuse_api_key: Optional[str] = None,
                 output_dir: str = "outputs"):
        self.vt_api_key = vt_api_key
        self.abuse_api_key = abuse_api_key
        self.output_dir = output_dir
        self.iocs: Dict[str, IOC] = {}   # key = f"{type}:{value}"
        self._ioc_counter = 0
        os.makedirs(output_dir, exist_ok=True)
        logger.info("[IOC] IOCExtractor initialized")
        if vt_api_key:
            logger.info("[IOC] VirusTotal enrichment: ENABLED")
        if abuse_api_key:
            logger.info("[IOC] AbuseIPDB enrichment: ENABLED")

    # ─── Main Extraction Method ───────────────────────────────────────────────
    def extract_from_packets(self, packets) -> List[IOC]:
        """Extract IOCs from parsed packet list."""
        logger.info(f"[EXTRACT] Processing {len(packets)} packets for IOCs...")

        ip_first_seen: Dict[str, str] = {}
        ip_last_seen: Dict[str, str] = {}
        ip_counts: Dict[str, int] = defaultdict(int)
        
        domain_first_seen: Dict[str, str] = {}
        domain_last_seen: Dict[str, str] = {}
        domain_counts: Dict[str, int] = defaultdict(int)

        url_counts: Dict[str, int] = defaultdict(int)
        ua_counts: Dict[str, int] = defaultdict(int)
        port_counts: Dict[int, int] = defaultdict(int)

        for pkt in packets:
            ts = pkt.timestamp

            # ── IP Extraction ──────────────────────────────────────────────────
            for ip_val in [pkt.src_ip, pkt.dst_ip]:
                if ip_val and ip_val not in ("0.0.0.0", "UNKNOWN"):
                    ip_counts[ip_val] += 1
                    if ip_val not in ip_first_seen:
                        ip_first_seen[ip_val] = ts
                    ip_last_seen[ip_val] = ts

            # ── Domain Extraction (DNS) ────────────────────────────────────────
            if pkt.dns_query:
                domain = pkt.dns_query.rstrip(".")
                domain_counts[domain] += 1
                if domain not in domain_first_seen:
                    domain_first_seen[domain] = ts
                domain_last_seen[domain] = ts

            # ── URL Extraction (HTTP) ──────────────────────────────────────────
            if pkt.http_host and pkt.http_uri:
                url = f"http://{pkt.http_host}{pkt.http_uri}"
                url_counts[url] += 1

            # ── User Agent Extraction ──────────────────────────────────────────
            if pkt.http_user_agent and pkt.is_suspicious:
                ua_counts[pkt.http_user_agent] += 1

            # ── Port Tracking ──────────────────────────────────────────────────
            if pkt.dst_port and pkt.dst_port in self.KNOWN_BAD_PORTS:
                port_counts[pkt.dst_port] += 1

        # ── Build IOC Objects ──────────────────────────────────────────────────
        for ip, count in ip_counts.items():
            if ip not in self.IP_WHITELIST:
                self._add_ip_ioc(ip, count, ip_first_seen[ip], ip_last_seen[ip])

        for domain, count in domain_counts.items():
            base_domain = self._extract_base_domain(domain)
            if base_domain not in self.DOMAIN_WHITELIST:
                self._add_domain_ioc(domain, count,
                                     domain_first_seen[domain], domain_last_seen[domain])

        for url, count in url_counts.items():
            self._add_url_ioc(url, count)

        for ua, count in ua_counts.items():
            self._add_ua_ioc(ua, count)

        for port, count in port_counts.items():
            self._add_port_ioc(port, count)

        logger.info(f"[EXTRACT] Extracted {len(self.iocs)} unique IOCs")
        return list(self.iocs.values())

    def extract_from_alerts(self, alerts) -> List[IOC]:
        """Cross-reference and tag IOCs based on generated alert data."""
        logger.info(f"[EXTRACT] Cross-referencing {len(alerts)} alerts with IOCs...")

        for alert in alerts:
            for ioc_val in alert.iocs:
                key_candidates = [
                    f"IP:{ioc_val}",
                    f"DOMAIN:{ioc_val}",
                    f"URL:{ioc_val}",
                    f"PORT:{ioc_val}",
                ]
                for key in key_candidates:
                    if key in self.iocs:
                        if alert.alert_id not in self.iocs[key].associated_alerts:
                            self.iocs[key].associated_alerts.append(alert.alert_id)
                        # Upgrade severity if alert is more severe
                        self.iocs[key].severity = self._max_severity(
                            self.iocs[key].severity, alert.severity
                        )
                        self.iocs[key].tags.append(alert.category)

        return list(self.iocs.values())

    # ─── IOC Factory Methods ──────────────────────────────────────────────────
    def _add_ip_ioc(self, ip: str, count: int, first_seen: str, last_seen: str):
        """Create or update an IP-type IOC."""
        key = f"IP:{ip}"
        if key in self.iocs:
            self.iocs[key].occurrence_count += count
            self.iocs[key].last_seen = last_seen
            return

        is_private = self._is_private_ip(ip)
        confidence = "HIGH" if not is_private and count > 10 else "MEDIUM"
        severity = "LOW"

        self._ioc_counter += 1
        self.iocs[key] = IOC(
            ioc_id=f"IOC-IP-{self._ioc_counter:04d}",
            ioc_type="IP",
            value=ip,
            confidence=confidence,
            severity=severity,
            first_seen=first_seen,
            last_seen=last_seen,
            occurrence_count=count,
            is_private=is_private,
            enrichment_status="PENDING" if not is_private else "SKIPPED"
        )

    def _add_domain_ioc(self, domain: str, count: int, first_seen: str, last_seen: str):
        """Create or update a Domain-type IOC."""
        key = f"DOMAIN:{domain}"
        if key in self.iocs:
            self.iocs[key].occurrence_count += count
            return

        entropy = self._calculate_entropy(domain)
        is_suspicious = len(domain) > 50 or entropy > 3.5
        confidence = "HIGH" if is_suspicious else "LOW"
        severity = "MEDIUM" if is_suspicious else "INFORMATIONAL"

        self._ioc_counter += 1
        self.iocs[key] = IOC(
            ioc_id=f"IOC-DOM-{self._ioc_counter:04d}",
            ioc_type="DOMAIN",
            value=domain,
            confidence=confidence,
            severity=severity,
            first_seen=first_seen,
            last_seen=last_seen,
            occurrence_count=count,
            tags=["HIGH_ENTROPY"] if entropy > 3.5 else []
        )

    def _add_url_ioc(self, url: str, count: int):
        """Create or update a URL-type IOC."""
        key = f"URL:{url}"
        if key in self.iocs:
            self.iocs[key].occurrence_count += count
            return

        self._ioc_counter += 1
        now = datetime.utcnow().isoformat()
        self.iocs[key] = IOC(
            ioc_id=f"IOC-URL-{self._ioc_counter:04d}",
            ioc_type="URL",
            value=url,
            confidence="MEDIUM",
            severity="MEDIUM",
            first_seen=now,
            last_seen=now,
            occurrence_count=count,
        )

    def _add_ua_ioc(self, user_agent: str, count: int):
        """Create or update a User-Agent-type IOC."""
        key = f"USER_AGENT:{user_agent}"
        if key in self.iocs:
            self.iocs[key].occurrence_count += count
            return

        self._ioc_counter += 1
        now = datetime.utcnow().isoformat()
        self.iocs[key] = IOC(
            ioc_id=f"IOC-UA-{self._ioc_counter:04d}",
            ioc_type="USER_AGENT",
            value=user_agent,
            confidence="HIGH",
            severity="HIGH",
            first_seen=now,
            last_seen=now,
            occurrence_count=count,
            tags=["MALICIOUS_TOOL"]
        )

    def _add_port_ioc(self, port: int, count: int):
        """Create or update a Port-type IOC."""
        key = f"PORT:{port}"
        if key in self.iocs:
            self.iocs[key].occurrence_count += count
            return

        self._ioc_counter += 1
        now = datetime.utcnow().isoformat()
        self.iocs[key] = IOC(
            ioc_id=f"IOC-PORT-{self._ioc_counter:04d}",
            ioc_type="PORT",
            value=str(port),
            confidence="HIGH",
            severity="HIGH",
            first_seen=now,
            last_seen=now,
            occurrence_count=count,
            tags=["KNOWN_MALWARE_PORT"]
        )

    # ─── API Enrichment ───────────────────────────────────────────────────────
    def enrich_iocs(self, max_enrichments: int = 20):
        """
        Enrich IP IOCs with VirusTotal and AbuseIPDB data.
        Rate-limited to avoid API quota exhaustion.
        """
        if not REQUESTS_AVAILABLE:
            logger.warning("[ENRICH] requests library not available")
            return

        enriched = 0
        for key, ioc in self.iocs.items():
            if enriched >= max_enrichments:
                break
            if ioc.ioc_type != "IP" or ioc.is_private or ioc.enrichment_status != "PENDING":
                continue

            if self.vt_api_key:
                self._enrich_virustotal(ioc)
                time.sleep(0.25)  # VT free tier: 4 req/sec

            if self.abuse_api_key:
                self._enrich_abuseipdb(ioc)
                time.sleep(0.1)

            ioc.enrichment_status = "ENRICHED"
            enriched += 1

        logger.info(f"[ENRICH] Enriched {enriched} IOCs")

    def _enrich_virustotal(self, ioc: IOC):
        """Query VirusTotal IP reputation API."""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc.value}"
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                ioc.vt_malicious_count = stats.get("malicious", 0)
                if ioc.vt_malicious_count and ioc.vt_malicious_count > 5:
                    ioc.severity = "CRITICAL"
                    ioc.confidence = "HIGH"
                    ioc.tags.append("VT_MALICIOUS")
                logger.info(f"[VT] {ioc.value}: {ioc.vt_malicious_count} malicious detections")
            else:
                logger.warning(f"[VT] API error {resp.status_code} for {ioc.value}")
        except Exception as e:
            logger.error(f"[VT] Request failed for {ioc.value}: {e}")

    def _enrich_abuseipdb(self, ioc: IOC):
        """Query AbuseIPDB confidence score."""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuse_api_key, "Accept": "application/json"}
            params = {"ipAddress": ioc.value, "maxAgeInDays": 90}
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                ioc.abuseipdb_score = data.get("abuseConfidenceScore", 0)
                ioc.abuseipdb_country = data.get("countryCode", "")
                ioc.geo_country = data.get("countryCode", "")
                if ioc.abuseipdb_score and ioc.abuseipdb_score > 75:
                    ioc.tags.append("ABUSEIPDB_HIGH_RISK")
                    ioc.severity = self._max_severity(ioc.severity, "HIGH")
                logger.info(f"[ABUSE] {ioc.value}: abuse score {ioc.abuseipdb_score}")
        except Exception as e:
            logger.error(f"[ABUSE] Request failed for {ioc.value}: {e}")

    # ─── Export Methods ───────────────────────────────────────────────────────
    def export_json(self, filename: str = "iocs.json") -> str:
        """Export IOC list to JSON."""
        path = os.path.join(self.output_dir, filename)
        output = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "total_iocs": len(self.iocs),
                "extractor_version": "2.0.0"
            },
            "ioc_summary": {
                "by_type": dict(Counter(i.ioc_type for i in self.iocs.values())),
                "by_severity": dict(Counter(i.severity for i in self.iocs.values())),
                "high_confidence": sum(1 for i in self.iocs.values() if i.confidence == "HIGH")
            },
            "iocs": [i.to_dict() for i in sorted(
                self.iocs.values(),
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}.get(x.severity, 5)
            )]
        }
        with open(path, "w") as f:
            json.dump(output, f, indent=2, default=str)
        logger.info(f"[EXPORT] IOC JSON: {path}")
        return path

    def export_csv(self, filename: str = "iocs.csv") -> str:
        """Export IOC list to CSV (compatible with threat intel platforms)."""
        path = os.path.join(self.output_dir, filename)
        ioc_list = list(self.iocs.values())
        if not ioc_list:
            return path
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=ioc_list[0].to_dict().keys())
            writer.writeheader()
            for ioc in ioc_list:
                row = ioc.to_dict()
                row["associated_alerts"] = "|".join(row["associated_alerts"])
                row["tags"] = "|".join(row["tags"])
                row["vt_detection_names"] = "|".join(row["vt_detection_names"])
                writer.writerow(row)
        logger.info(f"[EXPORT] IOC CSV: {path}")
        return path

    def export_stix_like(self, filename: str = "iocs_stix.json") -> str:
        """
        Export IOCs in a STIX 2.1-inspired JSON format.
        Suitable for sharing with threat intelligence platforms.
        """
        path = os.path.join(self.output_dir, filename)
        objects = []
        for ioc in self.iocs.values():
            if ioc.ioc_type == "IP":
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{ioc.ioc_id}",
                    "created": ioc.first_seen,
                    "modified": ioc.last_seen,
                    "name": f"Malicious IP: {ioc.value}",
                    "pattern": f"[ipv4-addr:value = '{ioc.value}']",
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen,
                    "confidence": {"HIGH": 85, "MEDIUM": 50, "LOW": 20}.get(ioc.confidence, 30),
                    "labels": ioc.tags
                }
                objects.append(obj)
        bundle = {
            "type": "bundle",
            "id": f"bundle--{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "objects": objects
        }
        with open(path, "w") as f:
            json.dump(bundle, f, indent=2)
        logger.info(f"[EXPORT] STIX bundle: {path}")
        return path

    # ─── Utility Methods ──────────────────────────────────────────────────────
    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in self.PRIVATE_RANGES)
        except ValueError:
            return False

    def _extract_base_domain(self, domain: str) -> str:
        """Extract registrable domain from FQDN."""
        parts = domain.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    def _calculate_entropy(self, text: str) -> float:
        import math
        from collections import Counter
        if not text:
            return 0.0
        freq = Counter(text.lower())
        total = len(text)
        return -sum((c/total) * math.log2(c/total) for c in freq.values())

    def _max_severity(self, s1: str, s2: str) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        return s1 if order.get(s1, 9) <= order.get(s2, 9) else s2
