import { useEffect, useState, useCallback } from 'react'
import { iocsApi } from '../api/client'
import type { IOC, IOCStats, WSMessage } from '../types'
import { SevBadge, Loading, ApiError } from '../components/ui'
import { useWebSocket } from '../hooks/useWebSocket'

const IOC_TYPES = ['', 'IP', 'DOMAIN', 'URL', 'USER_AGENT', 'PORT', 'HASH']
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

export function IOCsPage() {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [stats, setStats] = useState<IOCStats | null>(null)
  const [err, setErr] = useState('')
  const [type, setType] = useState('')
  const [sev, setSev] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<IOC | null>(null)
  const [total, setTotal] = useState(0)

  const load = useCallback(async () => {
    setErr('')
    try {
      const [r, s] = await Promise.all([
        iocsApi.list({ ioc_type: type || undefined, severity: sev || undefined, search: search || undefined, limit: 200 }),
        iocsApi.stats(),
      ])
      setIocs(r.iocs ?? r); setTotal(r.total ?? (r.iocs ?? r).length); setStats(s)
    } catch { setErr('Failed to fetch IOCs') }
  }, [type, sev, search])

  useEffect(() => { load() }, [load])

  const onWS = useCallback((msg: WSMessage) => {
    if (msg.type === 'new_ioc') {
      const ioc = msg.data as IOC
      setIocs(prev => [ioc, ...prev].slice(0, 200))
    }
  }, [])
  useWebSocket(onWS)

  if (!stats && !err && iocs.length === 0) return <Loading label="Loading IOCs from backend..." />
  if (err) return <ApiError msg={err} retry={load} />

  const typeColors: Record<string, string> = {
    IP: 'var(--critical)', DOMAIN: 'var(--accent)', URL: 'var(--high)',
    HASH: 'var(--accent2)', USER_AGENT: 'var(--medium)', PORT: 'var(--success)',
  }

  return (
    <div>
      <div className="page-header">
        <div className="page-title">◈ IOC <span>MANAGEMENT</span> — {total} indicators</div>
        <div style={{ display: 'flex', gap: 8 }}>
          <a className="btn btn-secondary btn-sm" href={iocsApi.exportCSVUrl()} download>↓ CSV</a>
          <a className="btn btn-secondary btn-sm" href={iocsApi.exportSTIXUrl()} download>↓ STIX2</a>
          <button className="btn btn-secondary btn-sm" onClick={load}>↻ Refresh</button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="stat-grid mb-4">
          <div className="stat-card"><div className="stat-val">{stats.total}</div><div className="stat-label">Total IOCs</div></div>
          {Object.entries(stats.type_distribution ?? {}).slice(0, 4).map(([k, v]) => (
            <div key={k} className="stat-card">
              <div className="stat-val" style={{ color: typeColors[k] ?? 'var(--accent)' }}>{v as number}</div>
              <div className="stat-label">{k}</div>
            </div>
          ))}
        </div>
      )}

      <div className="filter-bar">
        <input className="input" style={{ maxWidth: 220 }} placeholder="Search IOCs..." value={search}
          onChange={e => setSearch(e.target.value)} />
        <select className="input" value={type} onChange={e => setType(e.target.value)} style={{ maxWidth: 140 }}>
          {IOC_TYPES.map(t => <option key={t} value={t}>{t || 'All Types'}</option>)}
        </select>
        <select className="input" value={sev} onChange={e => setSev(e.target.value)} style={{ maxWidth: 160 }}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
        </select>
      </div>

      <div style={{ display: 'flex', gap: 16 }}>
        <div style={{ flex: 1, overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th>
                <th>Occurrences</th><th>Country</th><th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map(ioc => (
                <tr key={ioc.ioc_id}
                  style={{ cursor: 'pointer', background: selected?.ioc_id === ioc.ioc_id ? 'var(--bg-card-hover)' : '' }}
                  onClick={() => setSelected(ioc)}>
                  <td>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 11, padding: '2px 6px', borderRadius: 4,
                      background: 'var(--bg-secondary)', color: typeColors[ioc.ioc_type] ?? 'var(--text-secondary)' }}>
                      {ioc.ioc_type}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-primary)', maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</td>
                  <td><SevBadge sev={ioc.severity} /></td>
                  <td><span className={`badge badge-${ioc.confidence === 'HIGH' ? 'CRITICAL' : ioc.confidence === 'MEDIUM' ? 'MEDIUM' : 'LOW'}`}>{ioc.confidence}</span></td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{ioc.occurrence_count}</td>
                  <td style={{ fontSize: 12 }}>{ioc.geo_country ?? '—'}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ioc.last_seen?.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selected && (
          <div className="detail-panel" style={{ width: 300, flexShrink: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
              <SevBadge sev={selected.severity} />
              <button className="btn btn-secondary btn-sm" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 12, wordBreak: 'break-all', color: 'var(--accent)', marginBottom: 12 }}>{selected.value}</div>
            <div className="detail-row"><span className="detail-key">Type</span><span className="detail-val">{selected.ioc_type}</span></div>
            <div className="detail-row"><span className="detail-key">Confidence</span><span className="detail-val">{selected.confidence}</span></div>
            <div className="detail-row"><span className="detail-key">Occurrences</span><span className="detail-val">{selected.occurrence_count}</span></div>
            <div className="detail-row"><span className="detail-key">Country</span><span className="detail-val">{selected.geo_country ?? 'Unknown'}</span></div>
            <div className="detail-row"><span className="detail-key">Private IP</span><span className="detail-val">{selected.is_private ? 'Yes' : 'No'}</span></div>
            <div className="detail-row"><span className="detail-key">First Seen</span><span className="detail-val">{selected.first_seen?.slice(0, 10)}</span></div>
            <div className="detail-row"><span className="detail-key">Last Seen</span><span className="detail-val">{selected.last_seen?.slice(0, 10)}</span></div>
            {selected.abuseipdb_score !== null && (
              <div className="detail-row"><span className="detail-key">AbuseIPDB</span><span className="detail-val">{selected.abuseipdb_score}/100</span></div>
            )}
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Tags</div>
              <div>{(selected.tags ?? []).map(t => <span key={t} className="tag">{t}</span>)}</div>
            </div>
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Associated Alerts</div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>
                {(selected.associated_alerts ?? []).slice(0, 3).map(id => (
                  <div key={id} style={{ color: 'var(--text-muted)' }}>{id.slice(0, 12)}...</div>
                ))}
                {(selected.associated_alerts ?? []).length === 0 && <span style={{ color: 'var(--text-muted)' }}>None</span>}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
