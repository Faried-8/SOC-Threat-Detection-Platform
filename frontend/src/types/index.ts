// Auth
export interface User { username: string; role: string; full_name: string; }
export interface LoginResponse { access_token: string; token_type: string; user: User; }

// Alerts
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type AlertStatus = 'OPEN' | 'IN_PROGRESS' | 'CLOSED' | 'FALSE_POSITIVE';

export interface Alert {
  alert_id: string; timestamp: string; severity: Severity; category: string;
  title: string; description: string; src_ip: string; dst_ip: string;
  src_port: number | null; dst_port: number | null; protocol: string;
  mitre_technique: string; mitre_tactic: string; evidence: string[];
  iocs: string[]; analyst_notes: string; false_positive_likelihood: number;
  recommended_action: string; investigation_status: AlertStatus;
  is_false_positive: boolean; risk_score: number;
}

export interface AlertsResponse { total: number; offset: number; limit: number; alerts: Alert[]; }

export interface AlertStats {
  total: number; severity_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
  mitre_technique_counts: Record<string, number>;
  open: number; in_progress: number; closed: number; false_positives: number;
}

// IOCs
export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'USER_AGENT' | 'PORT' | 'HASH';
export interface IOC {
  ioc_id: string; ioc_type: IOCType; value: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW'; severity: Severity;
  first_seen: string; last_seen: string; occurrence_count: number;
  associated_alerts: string[]; tags: string[];
  vt_malicious_count: number | null; abuseipdb_score: number | null;
  geo_country: string | null; is_private: boolean; enrichment_status: string;
}
export interface IOCStats {
  total: number; type_distribution: Record<string, number>;
  severity_distribution: Record<string, number>;
  confidence_distribution: Record<string, number>;
}

// MITRE
export interface MitreTechnique {
  technique_id: string; name: string; tactic: string; tactic_id: string;
  description: string; alert_count: number; is_triggered: boolean;
  severity_distribution: Record<string, number>; alert_ids: string[];
  is_subtechnique: boolean; platforms: string[];
}
export interface MitreTactic {
  tactic_id: string; tactic_name: string;
  techniques: MitreTechnique[]; triggered_count: number;
}
export interface MitreMatrix {
  tactics: MitreTactic[]; total_techniques: number;
  triggered_techniques: number; technique_alert_map: Record<string, unknown>;
  data_source?: Record<string, unknown>;
}

// Traffic
export interface TrafficOverview {
  total_packets: number; total_bytes: number; unique_ips: number;
  protocols: Record<string, number>; top_talkers: Array<{ ip: string; bytes: number }>;
  suspicious_ratio: number;
}

// WebSocket events
export interface WSMessage {
  type: 'new_alert' | 'new_ioc' | 'stats_update' | 'pipeline_update' |
        'simulation_start' | 'simulation_progress' | 'simulation_complete' | string;
  data?: unknown;
  session_id?: string;
  stage?: string;
  progress?: number;
  message?: string;
  is_subtechnique?: boolean;
  platforms?: string[];
  // Simulation fields
  total_alerts?: number;
  current_alert?: string;
  total_alerts_generated?: number;
  [key: string]: unknown;
}
