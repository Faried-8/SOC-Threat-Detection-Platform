import { useState, useCallback } from 'react'
import { simulationApi } from '../api/client'
import type { Alert, WSMessage } from '../types'
import { SevBadge } from '../components/ui'
import { useWebSocket } from '../hooks/useWebSocket'

const SCENARIOS = [
  { id: 'port_scan', name: 'Port Scan', technique: 'T1046', severity: 'HIGH', desc: 'SYN scan across multiple ports, host discovery' },
  { id: 'dns_tunneling', name: 'DNS Tunneling', technique: 'T1071.004', severity: 'HIGH', desc: 'Covert data exfiltration via DNS queries' },
  { id: 'brute_force', name: 'Brute Force', technique: 'T1110', severity: 'HIGH', desc: 'Repeated auth failures against SSH/RDP services' },
  { id: 'c2_beaconing', name: 'C2 Beaconing', technique: 'T1071.001', severity: 'CRITICAL', desc: 'Regular callback intervals to C2 infrastructure' },
  { id: 'http_attack', name: 'HTTP Attack', technique: 'T1190', severity: 'HIGH', desc: 'Web application exploitation attempts' },
  { id: 'icmp_flood', name: 'ICMP Flood', technique: 'T1499', severity: 'MEDIUM', desc: 'DoS via ICMP packet flood' },
  { id: 'full', name: 'Full Attack Chain', technique: 'Multiple', severity: 'CRITICAL', desc: 'Complete kill chain: recon → initial access → C2 → exfil' },
]

export function SimulationPage() {
  const [selected, setSelected] = useState('full')
  const [speed, setSpeed] = useState('normal')
  const [running, setRunning] = useState(false)
  const [simId, setSimId] = useState('')
  const [events, setEvents] = useState<Alert[]>([])
  const [progress, setProgress] = useState(0)
  const [statusMsg, setStatusMsg] = useState('')
  const [totalExpected, setTotalExpected] = useState(0)

  const onWS = useCallback((msg: WSMessage) => {
    if (msg.type === 'new_alert') {
      const a = msg.data as Alert
      setEvents(prev => [a, ...prev].slice(0, 100))
    }
    if (msg.type === 'simulation_start') {
      setTotalExpected(msg.total_alerts ?? 0)
      setStatusMsg(`Simulation started — ${msg.total_alerts} alerts incoming`)
    }
    if (msg.type === 'simulation_progress') {
      setProgress(msg.progress ?? 0)
      setStatusMsg(`Detecting: ${msg.current_alert}`)
    }
    if (msg.type === 'simulation_complete') {
      setProgress(100)
      setStatusMsg(`✓ Complete — ${msg.total_alerts_generated} alerts generated`)
      setRunning(false)
    }
  }, [])

  useWebSocket(onWS)

  const start = async () => {
    setEvents([]); setProgress(0); setStatusMsg('Initializing...'); setRunning(true)
    try {
      const r = await simulationApi.start(selected, speed)
      setSimId(r.simulation_id)
      setStatusMsg(`Sim ${r.simulation_id} running — streaming via WebSocket`)
    } catch {
      setStatusMsg('Failed to start — is backend running?')
      setRunning(false)
    }
  }

  const scenario = SCENARIOS.find(s => s.id === selected)

  return (
    <div>
      <div className="page-header">
        <div className="page-title">▶ ATTACK <span>SIMULATION</span></div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
          Real-time threat detection via WebSocket
        </span>
      </div>

      <div className="grid-2">
        {/* Left: Config */}
        <div>
          <div className="card mb-4">
            <div className="section-title mb-3">Attack Scenario</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {SCENARIOS.map(sc => (
                <div key={sc.id}
                  className={`scenario-card ${selected === sc.id ? 'selected' : ''}`}
                  onClick={() => !running && setSelected(sc.id)}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{sc.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{sc.desc}</div>
                    </div>
                    <SevBadge sev={sc.severity} />
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--accent2)', marginTop: 4, fontFamily: 'var(--mono)' }}>
                    {sc.technique}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="section-title mb-3">Speed</div>
            <div style={{ display: 'flex', gap: 8 }}>
              {[
                { id: 'slow', label: 'Slow', hint: '3s/alert' },
                { id: 'normal', label: 'Normal', hint: '1.5s/alert' },
                { id: 'fast', label: 'Fast', hint: '0.5s/alert' },
              ].map(s => (
                <button key={s.id}
                  className={`btn btn-sm ${speed === s.id ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => !running && setSpeed(s.id)}>
                  {s.label}
                  <span style={{ fontSize: 9, opacity: 0.7 }}> ({s.hint})</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Live */}
        <div>
          <div className="card mb-4">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 14 }}>{scenario?.name}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{scenario?.desc}</div>
              </div>
              <button className="btn btn-primary" onClick={start} disabled={running}
                style={{ minWidth: 130, justifyContent: 'center' }}>
                {running ? '⚡ Detecting...' : '▶ Launch'}
              </button>
            </div>

            {/* Progress */}
            {(running || progress > 0) && (
              <div style={{ marginBottom: 12 }}>
                <div className="progress" style={{ height: 6, marginBottom: 6 }}>
                  <div className="progress-bar" style={{ width: `${progress}%`, transition: 'width 0.4s' }} />
                </div>
                <div style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--accent)', display: 'flex', justifyContent: 'space-between' }}>
                  <span>{statusMsg}</span>
                  <span>{progress}%</span>
                </div>
              </div>
            )}

            {simId && (
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                Session: {simId} · {events.length}/{totalExpected || '?'} events
              </div>
            )}
          </div>

          <div className="card" style={{ height: 480 }}>
            <div className="section-header mb-2">
              <div className="section-title">⚡ Live Event Stream</div>
              {events.length > 0 && (
                <button className="btn btn-secondary btn-sm" onClick={() => setEvents([])}>Clear</button>
              )}
            </div>
            <div style={{ overflowY: 'auto', height: 420 }}>
              {events.length === 0
                ? <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '40px 0', textAlign: 'center' }}>
                    <div style={{ fontSize: 32, marginBottom: 12 }}>▶</div>
                    Launch a simulation to see real-time attack events stream here via WebSocket
                  </div>
                : events.map((e, i) => (
                  <div key={`${e.alert_id}-${i}`} className="live-alert"
                    style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                      <SevBadge sev={e.severity} />
                      <span style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500 }}>{e.title}</span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)', display: 'flex', gap: 16 }}>
                      <span>{e.src_ip} → {e.dst_ip}</span>
                      <span className="tech-id">{e.mitre_technique}</span>
                      <span>{e.protocol}</span>
                    </div>
                  </div>
                ))
              }
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
