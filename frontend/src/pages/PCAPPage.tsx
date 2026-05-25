import { useState, useRef, useCallback, useEffect } from 'react'
import { pcapApi } from '../api/client'
import type { WSMessage } from '../types'
import { SevBadge } from '../components/ui'
import { useWebSocket } from '../hooks/useWebSocket'

interface PipelineStep {
  stage: string; progress: number; msg: string; done: boolean;
}

const PIPELINE_STAGES = [
  'Parsing packets', 'Protocol analysis', 'Threat detection',
  'IOC extraction', 'MITRE mapping', 'Report generation',
]

export function PCAPPage() {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [analyst, setAnalyst] = useState('SOC Analyst')
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [err, setErr] = useState('')
  const [steps, setSteps] = useState<PipelineStep[]>([])
  const [sessions, setSessions] = useState<Record<string, unknown>[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const sessionRef = useRef<string>('')

  // Load previous sessions
  useEffect(() => {
    pcapApi.sessions().then(r => setSessions(Array.isArray(r) ? r : r.sessions ?? [])).catch(() => {})
  }, [])

  const onWS = useCallback((msg: WSMessage) => {
    if (msg.type === 'pipeline_update') {
      const stage = msg.stage ?? ''
      const pct = msg.progress ?? 0
      const message = msg.message ?? ''
      setSteps(prev => {
        const existing = prev.find(s => s.stage === stage)
        if (existing) {
          return prev.map(s => s.stage === stage ? { ...s, progress: pct, msg: message, done: pct >= 100 } : s)
        }
        return [...prev, { stage, progress: pct, msg: message, done: pct >= 100 }]
      })
    }
  }, [])

  useWebSocket(onWS)

  const upload = async () => {
    if (!file) return
    setUploading(true); setErr(''); setResult(null); setSteps([])
    try {
      const r = await pcapApi.upload(file, analyst)
      setResult(r)
      sessionRef.current = r.analysis_id ?? ''
      // Reload sessions list
      pcapApi.sessions().then(res => setSessions(Array.isArray(res) ? res : res.sessions ?? [])).catch(() => {})
    } catch {
      setErr('Upload failed — ensure backend is running and file is a valid PCAP/PCAPNG')
    } finally { setUploading(false) }
  }

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f && (f.name.endsWith('.pcap') || f.name.endsWith('.pcapng') || f.name.endsWith('.cap'))) {
      setFile(f)
    } else if (f) {
      setErr('Please upload a .pcap, .pcapng, or .cap file')
    }
  }

  const overallProgress = steps.length === 0 ? 0 :
    Math.round(steps.reduce((sum, s) => sum + s.progress, 0) / Math.max(steps.length, 1))

  return (
    <div>
      <div className="page-header">
        <div className="page-title">⬚ PCAP <span>ANALYSIS</span></div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Upload PCAP → Cybersecurity Engine → Alerts + IOCs + MITRE mapping
        </span>
      </div>

      <div className="grid-2">
        {/* Upload panel */}
        <div>
          <div className="card mb-4">
            <div className="section-title mb-3">Upload PCAP File</div>
            <div
              className={`drop-zone ${dragging ? 'drag-over' : ''}`}
              onDragOver={e => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              onClick={() => inputRef.current?.click()}>
              <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap"
                style={{ display: 'none' }}
                onChange={e => { const f = e.target.files?.[0]; if (f) { setFile(f); setErr('') } }} />
              <div style={{ fontSize: 36, marginBottom: 8 }}>⬚</div>
              {file
                ? <div>
                    <div style={{ color: 'var(--accent)', fontSize: 13, fontWeight: 600 }}>{file.name}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 4 }}>
                      {(file.size / 1024).toFixed(1)} KB · click to change
                    </div>
                  </div>
                : <div>
                    <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Drop PCAP file here</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>.pcap · .pcapng · .cap</div>
                  </div>
              }
            </div>

            <div style={{ marginTop: 16 }}>
              <label className="form-label">Analyst Name</label>
              <input className="input" value={analyst}
                onChange={e => setAnalyst(e.target.value)}
                placeholder="SOC Analyst" />
            </div>

            {err && (
              <div style={{ marginTop: 12, padding: 10, background: 'rgba(239,68,68,0.1)',
                border: '1px solid rgba(239,68,68,0.25)', borderRadius: 6,
                fontSize: 12, color: 'var(--critical)' }}>
                {err}
              </div>
            )}

            <button className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: 16 }}
              onClick={upload} disabled={!file || uploading}>
              {uploading ? '⚡ Analyzing...' : '↑ Upload & Analyze'}
            </button>
          </div>

          {/* Pipeline progress */}
          {(uploading || steps.length > 0) && (
            <div className="card mb-4">
              <div className="section-title mb-3">Analysis Pipeline</div>
              <div className="progress" style={{ height: 8, marginBottom: 12 }}>
                <div className="progress-bar" style={{ width: `${overallProgress}%`, transition: 'width 0.5s' }} />
              </div>
              {steps.map((step, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <div style={{
                    width: 20, height: 20, borderRadius: '50%', flexShrink: 0,
                    background: step.done ? 'var(--success)' : 'var(--accent)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 10, fontWeight: 700, color: '#000',
                  }}>
                    {step.done ? '✓' : i + 1}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, color: 'var(--text-primary)' }}>{step.stage}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>{step.msg}</div>
                  </div>
                  <div style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--accent)', minWidth: 36, textAlign: 'right' }}>
                    {step.progress}%
                  </div>
                </div>
              ))}
              {uploading && steps.length === 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', fontSize: 12 }}>
                  <div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
                  Uploading and initializing pipeline...
                </div>
              )}
            </div>
          )}

          {/* Previous sessions */}
          {sessions.length > 0 && (
            <div className="card">
              <div className="section-title mb-3">Previous Sessions</div>
              {sessions.slice(0, 5).map((s, i) => {
                const sess = s as Record<string, unknown>
                return (
                  <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: 12 }}>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)' }}>
                      {sess.analysis_id as string ?? sess.session_id as string}
                    </div>
                    <div style={{ color: 'var(--text-muted)', marginTop: 2 }}>
                      {sess.pcap_file as string} · {sess.analyst_name as string}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Results panel */}
        <div>
          {result ? (
            <div className="card">
              <div className="section-title mb-3">✓ Analysis Results</div>

              <div className="stat-grid mb-4">
                <div className="stat-card critical">
                  <div className="stat-val critical">{(result.alerts as unknown[])?.length ?? 0}</div>
                  <div className="stat-label">Alerts Found</div>
                </div>
                <div className="stat-card success">
                  <div className="stat-val success">{(result.iocs as unknown[])?.length ?? 0}</div>
                  <div className="stat-label">IOCs Extracted</div>
                </div>
                <div className="stat-card">
                  <div className="stat-val">{(result.packets_analyzed as number) ?? 0}</div>
                  <div className="stat-label">Packets</div>
                </div>
              </div>

              {result.analysis_id && (
                <div className="detail-row">
                  <span className="detail-key">Session ID</span>
                  <span className="detail-val mono" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>
                    {result.analysis_id as string}
                  </span>
                </div>
              )}
              {result.analyst_name && (
                <div className="detail-row">
                  <span className="detail-key">Analyst</span>
                  <span className="detail-val">{result.analyst_name as string}</span>
                </div>
              )}
              {result.duration_seconds && (
                <div className="detail-row">
                  <span className="detail-key">Analysis Time</span>
                  <span className="detail-val">{(result.duration_seconds as number).toFixed(2)}s</span>
                </div>
              )}

              {(result.alerts as Record<string, unknown>[])?.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div className="section-title mb-2">Detected Threats</div>
                  {(result.alerts as Record<string, unknown>[]).slice(0, 10).map((a, i) => (
                    <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                        <SevBadge sev={a.severity as string} />
                        <span style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500 }}>{a.title as string}</span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)', display: 'flex', gap: 12 }}>
                        <span>{a.src_ip as string} → {a.dst_ip as string}</span>
                        <span style={{ color: 'var(--accent2)' }}>{a.mitre_technique as string}</span>
                      </div>
                    </div>
                  ))}
                  {(result.alerts as unknown[]).length > 10 && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>
                      ... and {(result.alerts as unknown[]).length - 10} more alerts
                    </div>
                  )}
                </div>
              )}

              {(result.iocs as Record<string, unknown>[])?.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div className="section-title mb-2">Extracted IOCs</div>
                  {(result.iocs as Record<string, unknown>[]).slice(0, 8).map((ioc, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 11 }}>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 10, padding: '1px 5px',
                        background: 'var(--bg-secondary)', borderRadius: 3, color: 'var(--accent)', flexShrink: 0 }}>
                        {ioc.ioc_type as string}
                      </span>
                      <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ioc.value as string}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="card" style={{ minHeight: 400, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16, color: 'var(--text-muted)' }}>
              <div style={{ fontSize: 56 }}>⬚</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)' }}>PCAP Analysis Engine</div>
              <div style={{ fontSize: 12, textAlign: 'center', maxWidth: 300, lineHeight: 1.6 }}>
                Upload a PCAP capture file to run it through the cybersecurity engine.
                The engine will extract packets, detect threats, map to MITRE ATT&CK, and extract IOCs.
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                <div>✓ Packet parsing & protocol analysis</div>
                <div>✓ Threat pattern detection</div>
                <div>✓ MITRE ATT&CK technique mapping</div>
                <div>✓ IOC extraction & enrichment</div>
                <div>✓ Real-time WebSocket progress updates</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
