"""
==============================================================================
Network Traffic Analysis & Threat Detection System
Module: Visualizer
Version: 2.0.0
==============================================================================

Description:
    Generates matplotlib/seaborn charts from traffic analysis and alert data.
    Produces PNG files suitable for incident reports and GitHub documentation.

Outputs:
    - Protocol distribution pie chart
    - Alert severity bar chart
    - Top talkers horizontal bar chart
    - Traffic timeline line chart
    - IOC type distribution chart
    - TCP flag distribution chart
==============================================================================
"""

import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger("Visualizer")

try:
    import matplotlib
    matplotlib.use("Agg")          # Non-interactive backend (no display needed)
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.gridspec import GridSpec
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.warning("[VIZ] matplotlib not available: pip install matplotlib numpy")


# ── Color Palette (SOC-themed dark style) ────────────────────────────────────
COLORS = {
    "CRITICAL":      "#FF3B3B",
    "HIGH":          "#FF8C00",
    "MEDIUM":        "#F59E0B",
    "LOW":           "#22C55E",
    "INFORMATIONAL": "#64748B",
    "TCP":  "#3B82F6",
    "HTTP": "#8B5CF6",
    "DNS":  "#06B6D4",
    "UDP":  "#22C55E",
    "ICMP": "#F59E0B",
    "OTHER":"#64748B",
}

CHART_STYLE = {
    "figure.facecolor":  "#0A0E1A",
    "axes.facecolor":    "#111827",
    "axes.edgecolor":    "#1E2D47",
    "axes.labelcolor":   "#94A3B8",
    "xtick.color":       "#64748B",
    "ytick.color":       "#64748B",
    "text.color":        "#E2E8F0",
    "grid.color":        "#1E2D47",
    "grid.linewidth":    0.5,
    "axes.titlecolor":   "#E2E8F0",
    "axes.titlesize":    11,
    "axes.labelsize":    9,
    "xtick.labelsize":   8,
    "ytick.labelsize":   8,
    "legend.facecolor":  "#1A2236",
    "legend.edgecolor":  "#1E2D47",
    "legend.fontsize":   8,
}


class Visualizer:
    """
    Traffic analysis visualization engine.
    Generates all charts as PNG files for report inclusion.
    """

    def __init__(self, output_dir: str = "outputs/charts"):
        if not MATPLOTLIB_AVAILABLE:
            raise RuntimeError("matplotlib required: pip install matplotlib numpy")
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        plt.rcParams.update(CHART_STYLE)
        logger.info(f"[VIZ] Visualizer initialized → {output_dir}")

    # ─── Chart 1: Protocol Distribution ──────────────────────────────────────
    def plot_protocol_distribution(self, protocol_counts: Dict[str, int],
                                   filename: str = "protocol_distribution.png") -> str:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle("Protocol Distribution", fontsize=13, fontweight="bold", y=1.02)

        protos = list(protocol_counts.keys())
        counts = list(protocol_counts.values())
        colors = [COLORS.get(p, "#475569") for p in protos]
        total  = sum(counts)

        # Pie chart
        wedges, texts, autotexts = ax1.pie(
            counts, labels=None, colors=colors,
            autopct=lambda p: f"{p:.1f}%" if p > 2 else "",
            startangle=90, pctdistance=0.75,
            wedgeprops={"linewidth": 1.5, "edgecolor": "#0A0E1A"}
        )
        for at in autotexts:
            at.set_fontsize(8)
            at.set_color("#E2E8F0")
        ax1.set_title("Protocol Mix", pad=12)
        ax1.legend(wedges, [f"{p} ({c:,})" for p, c in zip(protos, counts)],
                   loc="lower center", bbox_to_anchor=(0.5, -0.15), ncol=2)

        # Bar chart
        bars = ax2.barh(protos, counts, color=colors, edgecolor="#0A0E1A",
                        linewidth=0.5, height=0.6)
        for bar, count in zip(bars, counts):
            ax2.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                     f"{count:,} ({count/total*100:.1f}%)",
                     va="center", ha="left", fontsize=8, color="#94A3B8")
        ax2.set_xlabel("Packet Count")
        ax2.set_title("Volume by Protocol", pad=12)
        ax2.grid(axis="x", alpha=0.3)
        ax2.set_xlim(0, max(counts) * 1.25)
        ax2.invert_yaxis()

        plt.tight_layout()
        path = os.path.join(self.output_dir, filename)
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        logger.info(f"[VIZ] Protocol chart: {path}")
        return path

    # ─── Chart 2: Alert Severity Breakdown ───────────────────────────────────
    def plot_alert_severity(self, alerts, filename: str = "alert_severity.png") -> str:
        from collections import Counter
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        counts = Counter(getattr(a, "severity", a.get("severity", "")) for a in alerts)
        sevs   = [s for s in severity_order if counts.get(s, 0) > 0]
        vals   = [counts[s] for s in sevs]
        colors = [COLORS[s] for s in sevs]

        fig, ax = plt.subplots(figsize=(10, 4))
        bars = ax.bar(sevs, vals, color=colors, edgecolor="#0A0E1A", linewidth=0.5,
                      width=0.55)

        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                    str(val), ha="center", va="bottom", fontsize=10,
                    fontweight="bold", color="#E2E8F0")

        ax.set_title("Alert Severity Distribution", pad=12)
        ax.set_ylabel("Alert Count")
        ax.grid(axis="y", alpha=0.3)
        ax.set_ylim(0, max(vals) * 1.2 if vals else 1)

        plt.tight_layout()
        path = os.path.join(self.output_dir, filename)
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        logger.info(f"[VIZ] Severity chart: {path}")
        return path

    # ─── Chart 3: Top Talkers ─────────────────────────────────────────────────
    def plot_top_talkers(self, top_src_ips: List, top_dst_ips: List,
                         filename: str = "top_talkers.png") -> str:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
        fig.suptitle("Top Talkers Analysis", fontsize=13, fontweight="bold")

        def _plot_ips(ax, ip_data, title, color):
            ips    = [x[0] for x in ip_data[:10]]
            counts = [x[1] for x in ip_data[:10]]
            bars = ax.barh(range(len(ips)), counts, color=color, alpha=0.85,
                           edgecolor="#0A0E1A", linewidth=0.4, height=0.65)
            ax.set_yticks(range(len(ips)))
            ax.set_yticklabels(ips, fontsize=8, fontfamily="monospace")
            ax.invert_yaxis()
            ax.set_title(title, pad=10)
            ax.set_xlabel("Packet Count")
            ax.grid(axis="x", alpha=0.3)
            for bar, val in zip(bars, counts):
                ax.text(bar.get_width() + max(counts)*0.01,
                        bar.get_y() + bar.get_height()/2,
                        f"{val:,}", va="center", fontsize=7, color="#94A3B8")
            ax.set_xlim(0, max(counts) * 1.2 if counts else 1)

        _plot_ips(ax1, top_src_ips,  "Top Source IPs",      "#3B82F6")
        _plot_ips(ax2, top_dst_ips,  "Top Destination IPs", "#8B5CF6")

        plt.tight_layout()
        path = os.path.join(self.output_dir, filename)
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        logger.info(f"[VIZ] Top talkers chart: {path}")
        return path

    # ─── Chart 4: Traffic Timeline ────────────────────────────────────────────
    def plot_traffic_timeline(self, timeline: Dict[str, int],
                              filename: str = "traffic_timeline.png") -> str:
        if not timeline:
            logger.warning("[VIZ] No timeline data")
            return ""

        sorted_items = sorted(timeline.items())
        labels = [item[0] for item in sorted_items]
        values = [item[1] for item in sorted_items]

        fig, ax = plt.subplots(figsize=(14, 4))

        x = range(len(labels))
        ax.fill_between(x, values, alpha=0.15, color="#00D4FF")
        ax.plot(x, values, color="#00D4FF", linewidth=1.5, marker="o",
                markersize=3, markerfacecolor="#00D4FF")

        # Highlight peak
        if values:
            peak_idx = values.index(max(values))
            ax.axvline(peak_idx, color="#FF3B3B", linewidth=1, linestyle="--", alpha=0.6)
            ax.text(peak_idx, max(values) * 1.05,
                    f"Peak: {max(values)}", color="#FF3B3B", fontsize=8, ha="center")

        step = max(1, len(labels) // 10)
        ax.set_xticks(range(0, len(labels), step))
        ax.set_xticklabels([labels[i] for i in range(0, len(labels), step)],
                           rotation=30, ha="right", fontsize=7)
        ax.set_title("Traffic Volume Timeline (packets/minute)", pad=12)
        ax.set_ylabel("Packets")
        ax.grid(alpha=0.3)
        ax.set_xlim(0, len(labels) - 1)
        ax.set_ylim(0, max(values) * 1.2 if values else 1)

        plt.tight_layout()
        path = os.path.join(self.output_dir, filename)
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        logger.info(f"[VIZ] Timeline chart: {path}")
        return path

    # ─── Chart 5: IOC Type Distribution ──────────────────────────────────────
    def plot_ioc_distribution(self, iocs, filename: str = "ioc_distribution.png") -> str:
        from collections import Counter
        type_counts = Counter(getattr(i, "ioc_type", i.get("ioc_type", "")) for i in iocs)
        sev_counts  = Counter(getattr(i, "severity",  i.get("severity",  "")) for i in iocs)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        fig.suptitle("IOC Analysis", fontsize=13, fontweight="bold")

        # IOC types
        ioc_colors = {"IP":"#00D4FF","DOMAIN":"#8B5CF6","URL":"#22C55E",
                      "USER_AGENT":"#FF3B3B","PORT":"#F59E0B","HASH":"#94A3B8"}
        types  = list(type_counts.keys())
        tcvals = list(type_counts.values())
        tcolors = [ioc_colors.get(t, "#64748B") for t in types]
        ax1.bar(types, tcvals, color=tcolors, edgecolor="#0A0E1A", linewidth=0.5)
        ax1.set_title("IOC Types")
        ax1.set_ylabel("Count")
        ax1.grid(axis="y", alpha=0.3)
        for i, v in enumerate(tcvals):
            ax1.text(i, v + 0.1, str(v), ha="center", fontsize=9, color="#E2E8F0")

        # IOC severity
        sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"]
        sevs  = [s for s in sev_order if sev_counts.get(s, 0) > 0]
        svals = [sev_counts[s] for s in sevs]
        scolors = [COLORS[s] for s in sevs]
        ax2.pie(svals, labels=sevs, colors=scolors, autopct="%1.0f%%",
                startangle=90, textprops={"fontsize": 8, "color": "#E2E8F0"},
                wedgeprops={"edgecolor": "#0A0E1A", "linewidth": 1})
        ax2.set_title("IOC Severity Distribution")

        plt.tight_layout()
        path = os.path.join(self.output_dir, filename)
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        logger.info(f"[VIZ] IOC chart: {path}")
        return path

    # ─── Chart 6: Full Dashboard (combined) ──────────────────────────────────
    def plot_dashboard(self, traffic_profile, alerts, iocs,
                       filename: str = "soc_dashboard.png") -> str:
        """Generate a single combined dashboard image for reports."""
        fig = plt.figure(figsize=(16, 10))
        fig.suptitle(
            f"SOC Analysis Dashboard  |  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            fontsize=14, fontweight="bold", y=0.98
        )
        gs = GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35)

        from collections import Counter

        # ── Panel 1: Protocol pie ──────────────────────────────────────────────
        ax1 = fig.add_subplot(gs[0, 0])
        proto = getattr(traffic_profile, "protocol_distribution", {})
        if proto:
            vals   = list(proto.values())
            labels = list(proto.keys())
            colors = [COLORS.get(p, "#475569") for p in labels]
            ax1.pie(vals, labels=labels, colors=colors, autopct="%1.0f%%",
                    startangle=90, textprops={"fontsize": 7},
                    wedgeprops={"edgecolor": "#0A0E1A", "linewidth": 0.8})
        ax1.set_title("Protocol Distribution")

        # ── Panel 2: Severity bars ─────────────────────────────────────────────
        ax2 = fig.add_subplot(gs[0, 1])
        sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"]
        sev_c = Counter(getattr(a, "severity", "") for a in alerts)
        sevs  = [s for s in sev_order if sev_c.get(s, 0) > 0]
        if sevs:
            bars = ax2.bar(sevs, [sev_c[s] for s in sevs],
                           color=[COLORS[s] for s in sevs],
                           edgecolor="#0A0E1A", linewidth=0.5)
            for bar in bars:
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                         str(int(bar.get_height())), ha="center", fontsize=8)
        ax2.set_title("Alert Severity")
        ax2.grid(axis="y", alpha=0.3)
        ax2.tick_params(axis="x", labelrotation=15, labelsize=7)

        # ── Panel 3: Top source IPs ────────────────────────────────────────────
        ax3 = fig.add_subplot(gs[0, 2])
        top_src = getattr(traffic_profile, "top_src_ips", [])[:6]
        if top_src:
            ips  = [x[0] for x in top_src]
            cnts = [x[1] for x in top_src]
            ax3.barh(range(len(ips)), cnts, color="#3B82F6", alpha=0.85,
                     edgecolor="#0A0E1A")
            ax3.set_yticks(range(len(ips)))
            ax3.set_yticklabels(ips, fontsize=7, fontfamily="monospace")
            ax3.invert_yaxis()
            ax3.grid(axis="x", alpha=0.3)
        ax3.set_title("Top Source IPs")

        # ── Panel 4: Traffic timeline ──────────────────────────────────────────
        ax4 = fig.add_subplot(gs[1, :2])
        timeline = getattr(traffic_profile, "traffic_timeline", {})
        if timeline:
            sorted_tl = sorted(timeline.items())
            x = range(len(sorted_tl))
            y = [v for _, v in sorted_tl]
            ax4.fill_between(x, y, alpha=0.15, color="#00D4FF")
            ax4.plot(x, y, color="#00D4FF", linewidth=1.5)
            step = max(1, len(sorted_tl) // 8)
            ax4.set_xticks(range(0, len(sorted_tl), step))
            ax4.set_xticklabels([sorted_tl[i][0] for i in range(0, len(sorted_tl), step)],
                                 rotation=25, ha="right", fontsize=6)
            ax4.grid(alpha=0.3)
        ax4.set_title("Traffic Timeline (packets/min)")
        ax4.set_ylabel("Packets")

        # ── Panel 5: IOC breakdown ─────────────────────────────────────────────
        ax5 = fig.add_subplot(gs[1, 2])
        ioc_c = Counter(getattr(i, "ioc_type", "") for i in iocs)
        if ioc_c:
            ioc_types  = list(ioc_c.keys())
            ioc_vals   = list(ioc_c.values())
            ioc_colors = ["#00D4FF","#8B5CF6","#22C55E","#FF3B3B","#F59E0B"]
            ax5.bar(ioc_types, ioc_vals, color=ioc_colors[:len(ioc_types)],
                    edgecolor="#0A0E1A")
            ax5.tick_params(axis="x", labelrotation=20, labelsize=7)
            ax5.grid(axis="y", alpha=0.3)
        ax5.set_title("IOC Types")

        path = os.path.join(self.output_dir, filename)
        fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        logger.info(f"[VIZ] Dashboard chart: {path}")
        return path

    def generate_all(self, traffic_profile, alerts, iocs) -> Dict[str, str]:
        """Generate every chart and return paths dict."""
        paths = {}
        try:
            p = traffic_profile
            if getattr(p, "protocol_distribution", None):
                paths["protocol"] = self.plot_protocol_distribution(p.protocol_distribution)
            if alerts:
                paths["severity"] = self.plot_alert_severity(alerts)
            if getattr(p, "top_src_ips", None):
                paths["talkers"] = self.plot_top_talkers(p.top_src_ips, p.top_dst_ips)
            if getattr(p, "traffic_timeline", None):
                paths["timeline"] = self.plot_traffic_timeline(p.traffic_timeline)
            if iocs:
                paths["iocs"] = self.plot_ioc_distribution(iocs)
            paths["dashboard"] = self.plot_dashboard(p, alerts, iocs)
            logger.info(f"[VIZ] Generated {len(paths)} charts")
        except Exception as e:
            logger.error(f"[VIZ] Chart generation error: {e}")
        return paths
