import { useEffect, useState, useCallback } from 'react'
import { alertsApi } from '../api/client'
import type { Alert, AlertsResponse, WSMessage } from '../types'
import { SevBadge, StatusBadge, Loading, ApiError } from '../components/ui'
import { useWebSocket } from '../hooks/useWebSocket'

const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
const STATUSES = ['', 'OPEN', 'IN_PROGRESS', 'CLOSED', 'FALSE_POSITIVE']

export function AlertsPage() {
  const [data, setData] = useState<AlertsResponse | null>(null)
  const [err, setErr] = useState('')
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [updating, setUpdating] = useState(false)
  const [noteInput, setNoteInput] = useState('')
  const [liveNew, setLiveNew] = useState(0)

  const load = useCallback(async () => {
    setErr('')
    try {
      const r = await alertsApi.list({ severity: sev || undefined, status: status || undefined, search: search || undefined, limit: 100 })
      setData(r)
    } catch { setErr('Failed to fetch alerts') }
  }, [sev, status, search])

  useEffect(() => { load() }, [load])

  const onWS = useCallback((msg: WSMessage) => {
    if (msg.type === 'new_alert') {
      setLiveNew(n => n + 1)
      // prepend to list
      const a = msg.data as Alert
      setData(prev => prev ? { ...prev, total: prev.total + 1, alerts: [a, ...prev.alerts].slice(0, 100) } : prev)
    }
  }, [])
  useWebSocket(onWS)

  const updateStatus = async (newStatus: string) => {
    if (!selected) return
    setUpdating(true)
    try {
      await alertsApi.updateStatus(selected.alert_id, { status: newStatus, analyst_notes: noteInput || undefined })
      setSelected(prev => prev ? { ...prev, investigation_status: newStatus as Alert['investigation_status'] } : prev)
      load()
    } catch { /* ignore */ }
    finally { setUpdating(false) }
  }

  const markFP = async () => {
    if (!selected) return
    await alertsApi.updateStatus(selected.alert_id, { is_false_positive: true, status: 'FALSE_POSITIVE' })
    load()
  }

  if (!data && !err) return <Loading label="Loading alerts from backend..." />
  if (err) return <ApiError msg={err} retry={load} />

  return (
    <div>
      <div className="page-header">
        <div className="page-title">⚠ <span>ALERTS</span> — {data?.total ?? 0} total</div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {liveNew > 0 && (
            <span style={{ fontSize: 11, color: 'var(--critical)', fontFamily: 'var(--mono)' }}>
              +{liveNew} live
            </span>
          )}
          <button className="btn btn-secondary btn-sm" onClick={load}>↻ Refresh</button>
        </div>
      </div>

      <div className="filter-bar">
        <input className="input" style={{ maxWidth: 220 }} placeholder="Search alerts..." value={search}
          onChange={e => setSearch(e.target.value)} />
        <select className="input" value={sev} onChange={e => setSev(e.target.value)} style={{ maxWidth: 160 }}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
        </select>
        <select className="input" value={status} onChange={e => setStatus(e.target.value)} style={{ maxWidth: 160 }}>
          {STATUSES.map(s => <option key={s} value={s}>{s || 'All Statuses'}</option>)}
        </select>
      </div>

      <div style={{ display: 'flex', gap: 16 }}>
        {/* Alert list */}
        <div style={{ flex: 1, overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Sev</th><th>Title</th><th>Source IP</th><th>Dest IP</th>
                <th>MITRE</th><th>Status</th><th>Time</th>
              </tr>
            </thead>
            <tbody>
              {(data?.alerts ?? []).map(a => (
                <tr key={a.alert_id}
                  style={{ cursor: 'pointer', background: selected?.alert_id === a.alert_id ? 'var(--bg-card-hover)' : '' }}
                  onClick={() => { setSelected(a); setNoteInput(a.analyst_notes ?? '') }}>
                  <td><SevBadge sev={a.severity} /></td>
                  <td style={{ color: 'var(--text-primary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.title}</td>
                  <td><span className="ip">{a.src_ip}</span></td>
                  <td><span className="ip">{a.dst_ip}</span></td>
                  <td><span className="tech-id">{a.mitre_technique?.split(',')[0]}</span></td>
                  <td><StatusBadge status={a.investigation_status} /></td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{a.timestamp?.slice(0, 16).replace('T', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="detail-panel" style={{ width: 320, flexShrink: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <SevBadge sev={selected.severity} />
              <button className="btn btn-secondary btn-sm" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12, fontSize: 13 }}>
              {selected.title}
            </div>
            <div className="detail-row"><span className="detail-key">Alert ID</span><span className="detail-val">{selected.alert_id.slice(0, 8)}...</span></div>
            <div className="detail-row"><span className="detail-key">Source IP</span><span className="detail-val ip">{selected.src_ip}</span></div>
            <div className="detail-row"><span className="detail-key">Dest IP</span><span className="detail-val ip">{selected.dst_ip}</span></div>
            <div className="detail-row"><span className="detail-key">Protocol</span><span className="detail-val">{selected.protocol}</span></div>
            <div className="detail-row"><span className="detail-key">MITRE</span><span className="detail-val tech-id">{selected.mitre_technique}</span></div>
            <div className="detail-row"><span className="detail-key">Tactic</span><span className="detail-val">{selected.mitre_tactic}</span></div>
            <div className="detail-row"><span className="detail-key">Risk Score</span><span className="detail-val">{selected.risk_score}/100</span></div>
            <div className="detail-row"><span className="detail-key">Status</span><span className="detail-val"><StatusBadge status={selected.investigation_status} /></span></div>

            <div style={{ marginTop: 12, fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Description</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', background: 'var(--bg-secondary)', padding: 8, borderRadius: 4, marginBottom: 12 }}>{selected.description}</div>

            {selected.recommended_action && (
              <>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Recommended Action</div>
                <div style={{ fontSize: 12, color: 'var(--accent3)', background: 'var(--bg-secondary)', padding: 8, borderRadius: 4, marginBottom: 12 }}>{selected.recommended_action}</div>
              </>
            )}

            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Analyst Notes</div>
            <textarea className="input" rows={3} value={noteInput} onChange={e => setNoteInput(e.target.value)}
              placeholder="Add investigation notes..." style={{ resize: 'vertical', marginBottom: 10 }} />

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button className="btn btn-secondary btn-sm" onClick={() => updateStatus('IN_PROGRESS')} disabled={updating}>In Progress</button>
              <button className="btn btn-secondary btn-sm" onClick={() => updateStatus('CLOSED')} disabled={updating}>Close</button>
              <button className="btn btn-danger btn-sm" onClick={markFP} disabled={updating}>False Positive</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
