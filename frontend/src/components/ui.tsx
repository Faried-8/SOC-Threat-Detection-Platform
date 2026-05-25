import type { Severity, AlertStatus } from '../types'

export function SevBadge({ sev }: { sev: string }) {
  return <span className={`badge badge-${sev}`}>{sev}</span>
}

export function StatusBadge({ status }: { status: AlertStatus | string }) {
  return <span className={`badge badge-${status}`}>{status.replace('_', ' ')}</span>
}

export function Loading({ label = 'Loading...' }: { label?: string }) {
  return (
    <div className="loading-container">
      <div className="spinner" />
      <span style={{ fontSize: 12, fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>{label}</span>
    </div>
  )
}

export function ApiError({ msg, retry }: { msg: string; retry?: () => void }) {
  return (
    <div style={{ padding: 24, textAlign: 'center' }}>
      <div style={{ color: 'var(--critical)', marginBottom: 12 }}>⚠ {msg}</div>
      {retry && <button className="btn btn-secondary btn-sm" onClick={retry}>Retry</button>}
    </div>
  )
}

export function StatCard({ label, value, cls }: { label: string; value: string | number; cls?: string }) {
  return (
    <div className={`stat-card ${cls ?? ''}`}>
      <div className={`stat-val ${cls ?? ''}`}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

export function SevColor(sev: Severity | string): string {
  const m: Record<string, string> = {
    CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
    MEDIUM: 'var(--medium)', LOW: 'var(--low)', INFORMATIONAL: 'var(--info)',
  }
  return m[sev] ?? 'var(--text-muted)'
}
