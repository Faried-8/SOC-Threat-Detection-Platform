"""
==============================================================================
Network Traffic Analysis & Threat Detection System
Module: Report Generator
Version: 2.0.0
==============================================================================

Description:
    Enterprise-grade incident report generator. Produces professional
    investigation reports in multiple formats (JSON, CSV, plain text)
    following standard SOC incident documentation methodology.
==============================================================================
"""

import logging
import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger("ReportGenerator")


class ReportGenerator:
    """
    Generates professional SOC incident reports from analysis artifacts.
    Supports text, JSON, and CSV output formats.
    """

    SEVERITY_ICONS = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
        "INFORMATIONAL": "🔵"
    }

    def __init__(self, analyst_name: str = "SOC Analyst",
                 org_name: str = "Security Operations Center",
                 output_dir: str = "reports"):
        self.analyst_name = analyst_name
        self.org_name = org_name
        self.output_dir = output_dir
        self.report_id = f"IR-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"[REPORT] ReportGenerator initialized | Report ID: {self.report_id}")

    def generate_full_report(self, alerts, iocs, traffic_profile,
                              pcap_file: str = "unknown") -> str:
        """
        Generate the complete enterprise incident report as plain text.
        Follows standard SOC IR documentation structure.
        """
        lines = []
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        critical = [a for a in alerts if a.severity == "CRITICAL"]
        high     = [a for a in alerts if a.severity == "HIGH"]
        medium   = [a for a in alerts if a.severity == "MEDIUM"]
        low      = [a for a in alerts if a.severity in ("LOW", "INFORMATIONAL")]
        
        overall_severity = "CRITICAL" if critical else ("HIGH" if high else ("MEDIUM" if medium else "LOW"))
        icon = self.SEVERITY_ICONS.get(overall_severity, "⚪")

        # ══════════════════════════════════════════════════════════════════════
        lines += [
            "=" * 78,
            f"  NETWORK TRAFFIC ANALYSIS — INCIDENT REPORT",
            f"  {self.org_name}",
            "=" * 78,
            f"  Report ID       : {self.report_id}",
            f"  Classification  : {icon} {overall_severity}",
            f"  Generated       : {ts}",
            f"  Analyst         : {self.analyst_name}",
            f"  PCAP Source     : {pcap_file}",
            f"  Total Alerts    : {len(alerts)}  "
            f"(Critical: {len(critical)}  High: {len(high)}  "
            f"Medium: {len(medium)}  Low/Info: {len(low)})",
            "=" * 78,
            "",
        ]

        # ── 1. Executive Summary ───────────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 1 — EXECUTIVE SUMMARY",
            "━" * 78,
            "",
            f"  During analysis of network capture file '{pcap_file}', the SOC detection",
            f"  engine identified {len(alerts)} security alerts across {len(set(a.src_ip for a in alerts))}",
            f"  unique source IP addresses. The overall incident severity is rated {overall_severity}.",
            "",
            f"  Key findings include:",
        ]
        
        # Summarize top categories
        from collections import Counter
        categories = Counter(a.category for a in alerts)
        for cat, count in categories.most_common(5):
            lines.append(f"    • {cat.replace('_', ' ')}: {count} alert(s)")

        if critical:
            lines += [
                "",
                f"  ⚠  CRITICAL: {len(critical)} critical severity alert(s) require immediate",
                f"     investigation and containment action.",
            ]

        lines.append("")

        # ── 2. Scope & Methodology ────────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 2 — SCOPE & METHODOLOGY",
            "━" * 78,
            "",
            "  Scope:",
            f"    • Analysis target  : {pcap_file}",
            f"    • Total packets    : {getattr(traffic_profile, 'total_packets', 'N/A')}",
            f"    • Capture duration : {getattr(traffic_profile, 'capture_duration_seconds', 'N/A')}s",
            f"    • Analysis engine  : Network Traffic Analysis System v2.0.0",
            "",
            "  Methodology:",
            "    • Packet-level parsing using Scapy/PyShark",
            "    • Signature-based detection (known malicious patterns)",
            "    • Behavioral analysis (beaconing, scanning, volume anomalies)",
            "    • IOC extraction and correlation",
            "    • MITRE ATT&CK framework mapping",
            "",
        ]

        # ── 3. Traffic Statistics ──────────────────────────────────────────────
        if traffic_profile:
            p = traffic_profile
            lines += [
                "━" * 78,
                "  SECTION 3 — TRAFFIC STATISTICS",
                "━" * 78,
                "",
                f"  Volume Metrics:",
                f"    Total Packets        : {getattr(p, 'total_packets', 0):,}",
                f"    Total Bytes          : {getattr(p, 'total_bytes', 0):,} bytes",
                f"    Avg Packet Size      : {getattr(p, 'avg_packet_size', 0):.0f} bytes",
                f"    Packets/Second       : {getattr(p, 'packets_per_second', 0):.2f}",
                f"    Bytes/Second         : {getattr(p, 'bytes_per_second', 0):.2f}",
                "",
                f"  Protocol Distribution:",
            ]
            for proto, count in sorted(
                    getattr(p, 'protocol_distribution', {}).items(), key=lambda x: -x[1]):
                pct = getattr(p, 'protocol_percentages', {}).get(proto, 0)
                lines.append(f"    {proto:<15} : {count:>6} packets ({pct:.1f}%)")

            lines += [
                "",
                f"  Top Source IPs:",
            ]
            for ip, count in getattr(p, 'top_src_ips', [])[:5]:
                lines.append(f"    {ip:<20} : {count} packets")

            lines += [
                "",
                f"  Top Destination IPs:",
            ]
            for ip, count in getattr(p, 'top_dst_ips', [])[:5]:
                lines.append(f"    {ip:<20} : {count} packets")
            lines.append("")

        # ── 4. Threat Findings ────────────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 4 — THREAT FINDINGS",
            "━" * 78,
            "",
        ]

        for i, alert in enumerate(alerts, 1):
            icon = self.SEVERITY_ICONS.get(alert.severity, "⚪")
            lines += [
                f"  ┌─ Finding #{i:03d} {'─'*55}",
                f"  │  Alert ID   : {alert.alert_id}",
                f"  │  Severity   : {icon} {alert.severity}",
                f"  │  Category   : {alert.category}",
                f"  │  Title      : {alert.title}",
                f"  │  MITRE      : {alert.mitre_technique} ({alert.mitre_tactic})",
                f"  │  Source IP  : {alert.src_ip}",
                f"  │  Dest IP    : {alert.dst_ip}",
                f"  │  Protocol   : {alert.protocol}",
                f"  │  FP Risk    : {alert.false_positive_likelihood}",
                f"  │",
                f"  │  Description:",
            ]
            # Wrap description at 65 chars
            desc = alert.description
            while desc:
                chunk, desc = desc[:63], desc[63:]
                lines.append(f"  │    {chunk}")

            if alert.evidence:
                lines.append(f"  │  Evidence:")
                for ev in alert.evidence:
                    lines.append(f"  │    • {ev}")

            lines += [
                f"  │  Action Required:",
                f"  │    {alert.recommended_action[:70]}",
                f"  └{'─'*60}",
                "",
            ]

        # ── 5. IOC Summary ────────────────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 5 — INDICATORS OF COMPROMISE",
            "━" * 78,
            "",
        ]

        if iocs:
            from dataclasses import asdict
            ioc_list = [i for i in iocs if hasattr(i, 'severity')]
            by_type: Dict[str, List] = {}
            for ioc in ioc_list:
                by_type.setdefault(ioc.ioc_type, []).append(ioc)

            for ioc_type, type_iocs in by_type.items():
                lines.append(f"  {ioc_type} Indicators ({len(type_iocs)}):")
                for ioc in sorted(type_iocs, key=lambda x: x.occurrence_count, reverse=True)[:10]:
                    lines.append(
                        f"    [{ioc.severity:<13}] [{ioc.confidence:<6}] "
                        f"{ioc.value:<45} seen {ioc.occurrence_count}x"
                    )
                lines.append("")
        else:
            lines.append("  No IOCs extracted.\n")

        # ── 6. MITRE ATT&CK Summary ───────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 6 — MITRE ATT&CK MAPPING",
            "━" * 78,
            "",
        ]

        mitre_seen = {}
        for alert in alerts:
            key = f"{alert.mitre_technique} — {alert.mitre_tactic}"
            if key not in mitre_seen:
                mitre_seen[key] = {"technique": alert.mitre_technique,
                                   "tactic": alert.mitre_tactic,
                                   "count": 0, "categories": set()}
            mitre_seen[key]["count"] += 1
            mitre_seen[key]["categories"].add(alert.category)

        for key, data in sorted(mitre_seen.items(), key=lambda x: -x[1]["count"]):
            lines += [
                f"  Technique : {data['technique']}",
                f"  Tactic    : {data['mitre_tactic'] if 'mitre_tactic' in data else data['tactic']}",
                f"  Alert Cnt : {data['count']}",
                f"  Categories: {', '.join(data['categories'])}",
                "",
            ]

        # ── 7. Risk Assessment ────────────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 7 — RISK ASSESSMENT",
            "━" * 78,
            "",
            f"  Overall Risk Level : {overall_severity}",
            "",
            "  Risk Factors:",
        ]
        if critical:
            lines.append(f"    🔴 {len(critical)} CRITICAL alert(s) — Immediate response required")
        if high:
            lines.append(f"    🟠 {len(high)} HIGH severity alert(s) — Response within 1 hour")
        if medium:
            lines.append(f"    🟡 {len(medium)} MEDIUM severity alert(s) — Response within 24 hours")
        if low:
            lines.append(f"    🟢 {len(low)} LOW/INFO alert(s) — Monitor and document")
        lines.append("")

        # ── 8. Recommendations ───────────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 8 — RECOMMENDATIONS",
            "━" * 78,
            "",
            "  Immediate Actions (0–1 hour):",
            "    1. Block all CRITICAL and HIGH severity source IPs at perimeter firewall",
            "    2. Isolate any hosts exhibiting beaconing behavior",
            "    3. Preserve memory dumps from suspected compromised endpoints",
            "    4. Escalate to Incident Response team if C2 activity confirmed",
            "",
            "  Short-term Actions (1–24 hours):",
            "    5. Submit identified IOCs to threat intelligence platforms",
            "    6. Review SIEM for correlated events from flagged source IPs",
            "    7. Audit authentication logs on brute-force targeted systems",
            "    8. Patch all externally-facing web applications",
            "",
            "  Long-term Actions (1–7 days):",
            "    9.  Deploy Network Detection & Response (NDR) solution",
            "    10. Implement DNS response policy zone (RPZ) for malicious domains",
            "    11. Enable enhanced logging on all perimeter devices",
            "    12. Conduct threat hunt for lateral movement indicators",
            "",
        ]

        # ── 9. Conclusion ─────────────────────────────────────────────────────
        lines += [
            "━" * 78,
            "  SECTION 9 — CONCLUSION",
            "━" * 78,
            "",
            f"  This analysis identified {len(alerts)} security events from the provided",
            f"  network capture. The presence of {overall_severity}-severity indicators",
            f"  warrants {'immediate investigation' if overall_severity in ('CRITICAL','HIGH') else 'routine follow-up'}.",
            "",
            f"  Analyst  : {self.analyst_name}",
            f"  Report ID: {self.report_id}",
            f"  Date     : {ts}",
            "",
            "=" * 78,
            "  END OF REPORT — CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY",
            "=" * 78,
        ]

        report_text = "\n".join(lines)
        path = os.path.join(self.output_dir, f"{self.report_id}_incident_report.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(report_text)

        logger.info(f"[REPORT] Incident report written: {path}")
        print(report_text)
        return path

    def generate_csv_findings(self, alerts, filename: str = None) -> str:
        """Export alert findings to CSV format."""
        fname = filename or f"{self.report_id}_findings.csv"
        path = os.path.join(self.output_dir, fname)
        if not alerts:
            return path
        fields = [
            "alert_id", "timestamp", "severity", "category", "title",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "mitre_technique", "mitre_tactic", "false_positive_likelihood",
            "recommended_action"
        ]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for alert in alerts:
                writer.writerow({k: getattr(alert, k, "") for k in fields})
        logger.info(f"[REPORT] CSV findings: {path}")
        return path

    def generate_json_report(self, alerts, iocs, traffic_profile) -> str:
        """Export complete analysis as structured JSON."""
        path = os.path.join(self.output_dir, f"{self.report_id}_full_report.json")
        from dataclasses import asdict
        output = {
            "report_metadata": {
                "report_id": self.report_id,
                "generated_at": datetime.utcnow().isoformat(),
                "analyst": self.analyst_name,
                "organization": self.org_name,
                "tool": "Network Traffic Analysis System v2.0.0"
            },
            "summary": {
                "total_alerts": len(alerts),
                "by_severity": {
                    sev: sum(1 for a in alerts if a.severity == sev)
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
                },
                "total_iocs": len(iocs) if iocs else 0,
            },
            "traffic_profile": asdict(traffic_profile) if traffic_profile else {},
            "alerts": [a.to_dict() for a in alerts],
            "iocs": [i.to_dict() for i in iocs] if iocs else [],
        }
        with open(path, "w") as f:
            json.dump(output, f, indent=2, default=str)
        logger.info(f"[REPORT] JSON report: {path}")
        return path
