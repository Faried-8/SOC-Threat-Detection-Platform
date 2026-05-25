import { useEffect, useState } from 'react'
import { reportsApi, artifactsApi } from '../api/client'
import { Loading, SevBadge, StatusBadge } from '../components/ui'

export function ReportsPage() {
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null)
  const [incidents, setIncidents] = useState<Record<string, unknown>[]>([])
  const [artifacts, setArtifacts] = useState<unknown[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')

  useEffect(() => {
    Promise.all([reportsApi.summary(), reportsApi.incidents(), artifactsApi.list()])
      .then(([s, inc, art]) => {
        setSummary(s)
        setIncidents(inc.incidents ?? (Array.isArray(inc) ? inc : []))
        setArtifacts(art.artifacts ?? (Array.isArray(art) ? art : []))
      })
      .catch(() => setErr('Failed to load reports'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <Loading label="Loading reports..." />
  if (err) return <div style={{ color: 'var(--critical)', padding: 24 }}>{err}</div>

  const riskColor = (r: string) => ({
    CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
    MEDIUM: 'var(--medium)', LOW: 'var(--success)',
  }[r] ?? 'var(--text-muted)')

  return (
    <div>
      <div className="page-header">
        <div className="page-title">≡ <span>REPORTS</span> & ARTIFACTS</div>
      </div>

      {/* Executive Summary */}
      {summary && (
        <div className="card mb-4">
          <div className="section-title mb-3">Executive Summary — {summary.period as string}</div>
          <div className="stat-grid mb-4">
            <div className="stat-card">
              <div className="stat-val">{summary.total_alerts as number}</div>
              <div className="stat-label">Total Alerts</div>
            </div>
            <div className="stat-card critical">
              <div className="stat-val critical">{summary.critical_alerts as number}</div>
              <div className="stat-label">Critical</div>
            </div>
            <div className="stat-card high">
              <div className="stat-val high">{summary.high_alerts as number}</div>
              <div className="stat-label">High</div>
            </div>
            <div className="stat-card">
              <div className="stat-val" style={{ color: 'var(--high)' }}>{summary.open_alerts as number}</div>
              <div className="stat-label">Open Cases</div>
            </div>
            <div className="stat-card success">
              <div className="stat-val success">{summary.total_iocs as number}</div>
              <div className="stat-label">Active IOCs</div>
            </div>
            <div className="stat-card">
              <div className="stat-val" style={{ color: riskColor(summary.risk_level as string), fontSize: 20 }}>
                {summary.risk_level as string}
              </div>
              <div className="stat-label">Risk Level</div>
            </div>
          </div>

          <div className="grid-2">
            <div>
              <div className="detail-row">
                <span className="detail-key">Top MITRE Technique</span>
                <span className="detail-val tech-id">{summary.top_technique as string}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Generated At</span>
                <span className="detail-val">{(summary.generated_at as string)?.slice(0, 16).replace('T', ' ')} UTC</span>
              </div>
            </div>
            <div style={{
              padding: 12, background: 'var(--bg-secondary)', borderRadius: 6,
              fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6,
              borderLeft: `3px solid ${riskColor(summary.risk_level as string)}`,
            }}>
              <strong style={{ color: riskColor(summary.risk_level as string) }}>
                {summary.risk_level as string} RISK
              </strong>
              <br />
              {summary.recommendation as string}
            </div>
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Incidents */}
        <div className="card">
          <div className="section-title mb-3">Incident Report ({incidents.length})</div>
          {incidents.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '20px 0', textAlign: 'center' }}>
                No incidents — run a simulation or upload PCAPs to generate alerts
              </div>
            : <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr><th>ID</th><th>Title</th><th>Sev</th><th>Date</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {incidents.map((inc, i) => (
                      <tr key={i}>
                        <td><span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)' }}>{inc.incident_id as string}</span></td>
                        <td style={{ color: 'var(--text-primary)', fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.title as string}</td>
                        <td><SevBadge sev={inc.severity as string} /></td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{inc.date as string}</td>
                        <td><StatusBadge status={inc.status as string} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
          }
        </div>

        {/* Artifacts */}
        <div className="card">
          <div className="section-title mb-3">Analysis Artifacts</div>
          {artifacts.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '20px 0', textAlign: 'center' }}>
                No artifacts yet — PCAP analysis generates downloadable artifacts
              </div>
            : artifacts.map((art, i) => {
              const a = art as Record<string, unknown>
              return (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                  <div>
                    <div style={{ fontSize: 13, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>{a.filename as string}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                      {a.size as string} · {a.created as string}
                    </div>
                  </div>
                  <a className="btn btn-secondary btn-sm"
                    href={`/api/artifacts/download/${a.filename}`} download>
                    ↓ Download
                  </a>
                </div>
              )
            })
          }
        </div>
      </div>
    </div>
  )
}
