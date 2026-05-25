import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, AreaChart, Area, CartesianGrid, Legend,
} from 'recharts'
import { alertsApi, iocsApi, trafficApi, simulationApi } from '../api/client'
import { useWebSocket } from '../hooks/useWebSocket'
import type { AlertStats, IOCStats, Alert, WSMessage } from '../types'
import { Loading, SevBadge } from '../components/ui'

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308',
  LOW: '#3b82f6', INFORMATIONAL: '#6b7280',
}

const TOOLTIP_STYLE = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  fontSize: 11,
  fontFamily: 'var(--mono)',
}

export function DashboardPage() {
  const nav = useNavigate()
  const [alertStats, setAlertStats] = useState<AlertStats | null>(null)
  const [iocStats, setIocStats] = useState<IOCStats | null>(null)
  const [traffic, setTraffic] = useState<Record<string, unknown> | null>(null)
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([])
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [simRunning, setSimRunning] = useState(false)
  const [simMsg, setSimMsg] = useState('')

  const load = useCallback(async () => {
    try {
      const [as, is, tr, al] = await Promise.all([
        alertsApi.stats(), iocsApi.stats(), trafficApi.overview(),
        alertsApi.list({ limit: 15 }),
      ])
      setAlertStats(as); setIocStats(is); setTraffic(tr)
      setRecentAlerts(al.alerts ?? [])
    } catch { /* backend may not be up */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const onWS = useCallback((msg: WSMessage) => {
    if (msg.type === 'new_alert' && msg.data) {
      const a = msg.data as Alert
      setLiveAlerts(prev => [a, ...prev].slice(0, 25))
      setAlertStats(prev => prev ? {
        ...prev,
        total: prev.total + 1,
        open: prev.open + 1,
        severity_distribution: {
          ...prev.severity_distribution,
          [a.severity]: (prev.severity_distribution[a.severity] ?? 0) + 1,
        },
      } : prev)
    }
    if (msg.type === 'simulation_start') setSimMsg(`Simulation started — ${(msg as Record<string,unknown>).total_alerts as number} alerts incoming`)
    if (msg.type === 'simulation_progress') setSimMsg(`Progress: ${(msg as Record<string,unknown>).progress as number}% — ${(msg as Record<string,unknown>).current_alert as string}`)
    if (msg.type === 'simulation_complete') {
      setSimMsg('Simulation complete ✓')
      setSimRunning(false)
      setTimeout(() => load(), 1000) // reload stats after sim
    }
  }, [load])

  useWebSocket(onWS)

  const startSim = async () => {
    setSimRunning(true); setSimMsg('Starting...')
    try {
      await simulationApi.start('full', 'fast')
    } catch { setSimRunning(false); setSimMsg('Failed — is backend running?') }
  }

  if (loading) return <Loading label="Loading SOC dashboard..." />

  // Chart data
  const sevData = Object.entries(alertStats?.severity_distribution ?? {})
    .map(([name, value]) => ({ name, value }))
  const catData = Object.entries(alertStats?.category_distribution ?? {})
    .slice(0, 6).map(([name, value]) => ({ name: name.replace('_', ' ').slice(0, 14), value }))
  const mitreTop = Object.entries(alertStats?.mitre_technique_counts ?? {})
    .sort((a, b) => +b[1] - +a[1]).slice(0, 8)
  const protoData = Object.entries((traffic?.protocol_distribution ?? traffic?.protocols ?? {}) as Record<string, number>)
    .map(([name, value]) => ({ name, value }))
  const maxMitre = mitreTop[0] ? +mitreTop[0][1] : 1

  return (
    <div>
      <div className="page-header">
        <div className="page-title">⬡ SOC <span>DASHBOARD</span></div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {simMsg && <span style={{ fontSize: 11, color: 'var(--accent)', fontFamily: 'var(--mono)' }}>{simMsg}</span>}
          <button className="btn btn-secondary btn-sm" onClick={load}>↻ Refresh</button>
          <button className="btn btn-primary btn-sm" onClick={startSim} disabled={simRunning}>
            {simRunning ? '⚡ Running...' : '▶ Run Sim'}
          </button>
        </div>
      </div>

      {/* Stat grid */}
      <div className="stat-grid mb-4">
        <div className="stat-card critical">
          <div className="stat-val critical">{alertStats?.severity_distribution?.CRITICAL ?? 0}</div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat-card high">
          <div className="stat-val high">{alertStats?.severity_distribution?.HIGH ?? 0}</div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat-card">
          <div className="stat-val">{alertStats?.total ?? 0}</div>
          <div className="stat-label">Total Alerts</div>
        </div>
        <div className="stat-card">
          <div className="stat-val" style={{ color: 'var(--high)' }}>{alertStats?.open ?? 0}</div>
          <div className="stat-label">Open Cases</div>
        </div>
        <div className="stat-card success">
          <div className="stat-val success">{iocStats?.total ?? 0}</div>
          <div className="stat-label">Active IOCs</div>
        </div>
        <div className="stat-card">
          <div className="stat-val">{(traffic?.unique_ips as number) ?? 0}</div>
          <div className="stat-label">Unique IPs</div>
        </div>
        <div className="stat-card">
          <div className="stat-val" style={{ fontSize: 20 }}>
            {(((traffic?.total_packets as number) ?? 0) / 1000).toFixed(1)}K
          </div>
          <div className="stat-label">Packets</div>
        </div>
        <div className="stat-card">
          <div className="stat-val" style={{ fontSize: 20 }}>
            {alertStats?.false_positives ?? 0}
          </div>
          <div className="stat-label">False Positives</div>
        </div>
      </div>

      {/* Row 1: Severity pie + Category bar */}
      <div className="grid-2 mb-4">
        <div className="card">
          <div className="section-header">
            <div className="section-title">Alert Severity Distribution</div>
          </div>
          {sevData.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '40px 0', textAlign: 'center' }}>No alert data yet</div>
            : <ResponsiveContainer width="100%" height={210}>
                <PieChart>
                  <Pie data={sevData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                    dataKey="value" paddingAngle={2}>
                    {sevData.map(({ name }) => (
                      <Cell key={name} fill={SEV_COLORS[name] ?? '#6b7280'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Legend formatter={(v) => <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{v}</span>} />
                </PieChart>
              </ResponsiveContainer>
          }
        </div>

        <div className="card">
          <div className="section-header">
            <div className="section-title">Alert Categories</div>
          </div>
          {catData.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '40px 0', textAlign: 'center' }}>No category data yet</div>
            : <ResponsiveContainer width="100%" height={210}>
                <BarChart data={catData} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={100}
                    tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="value" fill="var(--accent)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
          }
        </div>
      </div>

      {/* Row 2: MITRE top + Protocol distribution */}
      <div className="grid-2 mb-4">
        <div className="card">
          <div className="section-header">
            <div className="section-title">Top MITRE Techniques</div>
            <button className="btn btn-secondary btn-sm" onClick={() => nav('/mitre')}>Matrix →</button>
          </div>
          {mitreTop.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '20px 0' }}>
                Run a simulation to see MITRE technique detections
              </div>
            : mitreTop.map(([tech, count]) => (
              <div key={tech} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span className="tech-id" style={{ minWidth: 70 }}>{tech}</span>
                <div className="progress" style={{ flex: 1 }}>
                  <div className="progress-bar"
                    style={{ width: `${(+count / maxMitre) * 100}%` }} />
                </div>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-secondary)', minWidth: 24, textAlign: 'right' }}>
                  {count as number}
                </span>
              </div>
            ))
          }
        </div>

        <div className="card">
          <div className="section-header">
            <div className="section-title">Protocol Distribution</div>
          </div>
          {protoData.length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '40px 0', textAlign: 'center' }}>No traffic data</div>
            : <ResponsiveContainer width="100%" height={210}>
                <BarChart data={protoData} margin={{ left: 0, right: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                  <Bar dataKey="value" fill="var(--accent2)" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
          }
        </div>
      </div>

      {/* Row 3: Live feed + Recent alerts table */}
      <div className="grid-2 mb-4">
        <div className="card">
          <div className="section-header">
            <div className="section-title">⚡ Live Alert Feed</div>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
              {liveAlerts.length} streamed
            </span>
          </div>
          <div style={{ maxHeight: 260, overflowY: 'auto' }}>
            {liveAlerts.length === 0
              ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '30px 0', textAlign: 'center' }}>
                  WebSocket connected — alerts will appear here in real-time
                </div>
              : liveAlerts.map((a, i) => (
                <div key={`${a.alert_id}-${i}`} className="live-alert"
                  style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                  <SevBadge sev={a.severity} />
                  <span style={{ flex: 1, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.title}
                  </span>
                  <span className="ip">{a.src_ip}</span>
                </div>
              ))
            }
          </div>
        </div>

        <div className="card">
          <div className="section-header">
            <div className="section-title">IOC Type Breakdown</div>
            <button className="btn btn-secondary btn-sm" onClick={() => nav('/iocs')}>All IOCs →</button>
          </div>
          {Object.keys(iocStats?.type_distribution ?? {}).length === 0
            ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '40px 0', textAlign: 'center' }}>No IOC data</div>
            : <ResponsiveContainer width="100%" height={210}>
                <PieChart>
                  <Pie
                    data={Object.entries(iocStats?.type_distribution ?? {}).map(([name, value]) => ({ name, value }))}
                    cx="50%" cy="50%" outerRadius={85} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    labelLine={false} style={{ fontSize: 10 }}>
                    {Object.keys(iocStats?.type_distribution ?? {}).map((_, i) => (
                      <Cell key={i} fill={['#ef4444','#00d4ff','#f97316','#7c3aed','#10b981','#eab308'][i % 6]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
          }
        </div>
      </div>

      {/* Recent alerts table */}
      <div className="card">
        <div className="section-header">
          <div className="section-title">Recent Alerts</div>
          <button className="btn btn-secondary btn-sm" onClick={() => nav('/alerts')}>View All →</button>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th><th>Title</th><th>Source IP</th>
                <th>Category</th><th>MITRE</th><th>Status</th><th>Time</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.length === 0
                ? <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>
                    No alerts yet — run a simulation or upload a PCAP
                  </td></tr>
                : recentAlerts.map(a => (
                  <tr key={a.alert_id} style={{ cursor: 'pointer' }} onClick={() => nav('/alerts')}>
                    <td><SevBadge sev={a.severity} /></td>
                    <td style={{ color: 'var(--text-primary)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.title}
                    </td>
                    <td><span className="ip">{a.src_ip}</span></td>
                    <td><span className="tag">{a.category}</span></td>
                    <td><span className="tech-id">{(a.mitre_technique ?? '').split(',')[0]}</span></td>
                    <td>
                      <span className={`badge badge-${a.investigation_status}`}>
                        {a.investigation_status?.replace('_', ' ')}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {(a.timestamp ?? '').slice(0, 16).replace('T', ' ')}
                    </td>
                  </tr>
                ))
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
