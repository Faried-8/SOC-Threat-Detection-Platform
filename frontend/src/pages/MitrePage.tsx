import { useEffect, useState, useCallback } from 'react'
import { mitreApi } from '../api/client'
import type { MitreMatrix, MitreTechnique, MitreTactic } from '../types'
import { Loading, ApiError } from '../components/ui'

type View = 'matrix' | 'heatmap' | 'list'

function heatColor(count: number, max: number): string {
  if (count === 0) return 'var(--bg-card)'
  const r = count / Math.max(max, 1)
  if (r > 0.7) return 'rgba(239,68,68,0.85)'
  if (r > 0.4) return 'rgba(249,115,22,0.75)'
  if (r > 0.2) return 'rgba(234,179,8,0.65)'
  return 'rgba(59,130,246,0.55)'
}

export function MitrePage() {
  const [matrix, setMatrix] = useState<MitreMatrix | null>(null)
  const [dataSource, setDataSource] = useState<Record<string, unknown> | null>(null)
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState<MitreTechnique | null>(null)
  const [techDetail, setTechDetail] = useState<Record<string, unknown> | null>(null)
  const [view, setView] = useState<View>('matrix')
  const [filterTactic, setFilterTactic] = useState('')
  const [showSubs, setShowSubs] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  const load = useCallback(async () => {
    setErr('')
    try {
      const data = await mitreApi.matrix()
      setMatrix(data)
      setDataSource(data.data_source ?? null)
    } catch (e) {
      setErr('Failed to load MITRE matrix from backend')
    }
  }, [])

  useEffect(() => { load() }, [load])

  const refresh = async () => {
    setRefreshing(true)
    try { await mitreApi.refresh(); await load() }
    catch { /* ignore */ }
    finally { setRefreshing(false) }
  }

  const selectTech = async (tech: MitreTechnique) => {
    setSelected(tech); setTechDetail(null)
    try {
      const d = await mitreApi.technique(tech.technique_id)
      setTechDetail(d)
    } catch { /* ignore */ }
  }

  if (!matrix && !err) return <Loading label="Loading live MITRE ATT&CK data..." />
  if (err) return <ApiError msg={err} retry={load} />

  // Filter by subtechniques and tactic
  let tactics = matrix!.tactics
  if (filterTactic) tactics = tactics.filter(t => t.tactic_name === filterTactic)

  const filteredTactics = tactics.map(t => ({
    ...t,
    techniques: showSubs ? t.techniques : t.techniques.filter((tech: MitreTechnique) => !tech.is_subtechnique),
  }))

  const allTechs = matrix!.tactics.flatMap(t =>
    (showSubs ? t.techniques : t.techniques.filter((tech: MitreTechnique) => !tech.is_subtechnique)) as MitreTechnique[]
  )
  const maxCount = Math.max(...allTechs.map(t => t.alert_count), 1)
  const triggeredTechs = allTechs.filter(t => t.alert_count > 0)

  return (
    <div>
      <div className="page-header">
        <div className="page-title">⬢ MITRE <span>ATT&CK</span></div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          {dataSource && (
            <span style={{
              fontSize: 10, fontFamily: 'var(--mono)', padding: '2px 8px',
              background: (dataSource.source as string)?.includes('live') ? 'rgba(16,185,129,0.15)' : 'rgba(107,114,128,0.15)',
              color: (dataSource.source as string)?.includes('live') ? 'var(--success)' : 'var(--text-muted)',
              borderRadius: 4, border: `1px solid ${(dataSource.source as string)?.includes('live') ? 'rgba(16,185,129,0.3)' : 'var(--border)'}`,
            }}>
              {(dataSource.source as string)?.includes('live') ? '● LIVE STIX2' : '○ BUNDLED'} · {dataSource.techniques_count as number} techniques
            </span>
          )}
          {([
            { v: 'matrix', l: 'Matrix' },
            { v: 'heatmap', l: 'Heatmap' },
            { v: 'list', l: 'List' },
          ] as { v: View; l: string }[]).map(({ v, l }) => (
            <button key={v} className={`btn btn-sm ${view === v ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setView(v)}>{l}</button>
          ))}
          <button className="btn btn-secondary btn-sm" onClick={refresh} disabled={refreshing}>
            {refreshing ? '⟳ Refreshing...' : '⟳ Refresh STIX2'}
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="stat-grid mb-4">
        <div className="stat-card">
          <div className="stat-val">{matrix!.total_techniques}</div>
          <div className="stat-label">Total Techniques</div>
        </div>
        <div className="stat-card critical">
          <div className="stat-val critical">{matrix!.triggered_techniques}</div>
          <div className="stat-label">Triggered</div>
        </div>
        <div className="stat-card">
          <div className="stat-val">{matrix!.tactics.length}</div>
          <div className="stat-label">Tactics</div>
        </div>
        <div className="stat-card success">
          <div className="stat-val success">
            {matrix!.total_techniques > 0
              ? `${((matrix!.triggered_techniques / matrix!.total_techniques) * 100).toFixed(1)}%`
              : '0%'}
          </div>
          <div className="stat-label">Coverage</div>
        </div>
      </div>

      {/* Filters */}
      <div className="filter-bar mb-4">
        <select className="input" value={filterTactic} onChange={e => setFilterTactic(e.target.value)} style={{ maxWidth: 220 }}>
          <option value="">All Tactics ({matrix!.tactics.length})</option>
          {matrix!.tactics.map((t: MitreTactic) => (
            <option key={t.tactic_id} value={t.tactic_name}>
              {t.tactic_name} ({t.triggered_count} triggered)
            </option>
          ))}
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer' }}>
          <input type="checkbox" checked={showSubs} onChange={e => setShowSubs(e.target.checked)} />
          Show sub-techniques
        </label>
        {triggeredTechs.length > 0 && (
          <span style={{ fontSize: 11, color: 'var(--critical)', fontFamily: 'var(--mono)', marginLeft: 8 }}>
            ⚠ {triggeredTechs.length} active detections
          </span>
        )}
      </div>

      <div style={{ display: 'flex', gap: 16 }}>
        {/* Main view */}
        <div style={{ flex: 1, minWidth: 0 }}>

          {view === 'matrix' && (
            <div style={{ overflowX: 'auto', paddingBottom: 8 }}>
              <div style={{ display: 'flex', gap: 4, minWidth: 'max-content' }}>
                {filteredTactics.map((tactic: MitreTactic) => (
                  <div key={tactic.tactic_id} style={{ minWidth: 130, maxWidth: 150 }}>
                    <div style={{
                      background: tactic.triggered_count > 0 ? 'rgba(239,68,68,0.1)' : 'var(--bg-secondary)',
                      border: `1px solid ${tactic.triggered_count > 0 ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
                      borderRadius: '6px 6px 0 0', padding: '8px 6px', fontSize: 10,
                      fontWeight: 700, textAlign: 'center',
                      color: tactic.triggered_count > 0 ? 'var(--high)' : 'var(--text-muted)',
                      textTransform: 'uppercase', letterSpacing: '0.04em',
                    }}>
                      {tactic.tactic_name}
                      {tactic.triggered_count > 0 && (
                        <div style={{ color: 'var(--critical)', fontSize: 10 }}>⚠ {tactic.triggered_count}</div>
                      )}
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, paddingTop: 2 }}>
                      {(tactic.techniques as MitreTechnique[]).map(tech => (
                        <div key={tech.technique_id}
                          onClick={() => selectTech(tech)}
                          style={{
                            padding: '5px 7px', borderRadius: 4, fontSize: 11, cursor: 'pointer',
                            border: `1px solid ${selected?.technique_id === tech.technique_id ? 'var(--accent)' : tech.is_triggered ? 'rgba(239,68,68,0.35)' : 'var(--border)'}`,
                            background: selected?.technique_id === tech.technique_id
                              ? 'rgba(0,212,255,0.12)'
                              : tech.is_triggered ? 'rgba(239,68,68,0.08)' : 'var(--bg-card)',
                            transition: 'all 0.12s',
                          }}>
                          <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--accent2)' }}>
                            {tech.technique_id}
                          </div>
                          <div style={{ fontSize: 10, color: 'var(--text-secondary)', lineHeight: 1.3, marginTop: 2 }}>
                            {tech.name}
                          </div>
                          {tech.alert_count > 0 && (
                            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--critical)', marginTop: 2 }}>
                              ⚠ {tech.alert_count}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {view === 'heatmap' && (
            <div style={{ overflowX: 'auto', paddingBottom: 8 }}>
              <div style={{ display: 'flex', gap: 4, minWidth: 'max-content' }}>
                {filteredTactics.map((tactic: MitreTactic) => (
                  <div key={tactic.tactic_id} style={{ minWidth: 80 }}>
                    <div style={{
                      fontSize: 9, color: 'var(--text-muted)', textAlign: 'center',
                      padding: '4px 2px', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 4,
                    }}>
                      {tactic.tactic_name.slice(0, 11)}
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      {(tactic.techniques as MitreTechnique[]).map(tech => (
                        <div key={tech.technique_id}
                          onClick={() => selectTech(tech)}
                          title={`${tech.technique_id}: ${tech.name} (${tech.alert_count} alerts)`}
                          style={{
                            width: '100%', height: 34, borderRadius: 4,
                            background: heatColor(tech.alert_count, maxCount),
                            border: `1px solid ${tech.alert_count > 0 ? 'rgba(255,255,255,0.15)' : 'var(--border)'}`,
                            cursor: 'pointer', transition: 'transform 0.1s',
                            display: 'flex', flexDirection: 'column',
                            alignItems: 'center', justifyContent: 'center',
                          }}
                          onMouseEnter={e => (e.currentTarget.style.transform = 'scale(1.1)')}
                          onMouseLeave={e => (e.currentTarget.style.transform = 'scale(1)')}>
                          <div style={{ fontSize: 8, fontFamily: 'var(--mono)', color: tech.alert_count > 0 ? '#fff' : 'var(--text-muted)' }}>
                            {tech.technique_id}
                          </div>
                          {tech.alert_count > 0 && (
                            <div style={{ fontSize: 11, fontWeight: 700, color: '#fff' }}>{tech.alert_count}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              {/* Legend */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, fontSize: 10, color: 'var(--text-muted)' }}>
                <span>Alert density:</span>
                {['0','Low','Med','High','Critical'].map((l, i) => (
                  <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                    <div style={{
                      width: 16, height: 16, borderRadius: 3,
                      background: ['var(--bg-card)','rgba(59,130,246,0.55)','rgba(234,179,8,0.65)','rgba(249,115,22,0.75)','rgba(239,68,68,0.85)'][i],
                      border: '1px solid var(--border)',
                    }} />
                    <span>{l}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {view === 'list' && (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th><th>Name</th><th>Tactic</th>
                    <th>Alerts</th><th>Platforms</th><th>Sub?</th>
                  </tr>
                </thead>
                <tbody>
                  {allTechs.sort((a, b) => b.alert_count - a.alert_count).map(tech => (
                    <tr key={tech.technique_id}
                      style={{ cursor: 'pointer', background: selected?.technique_id === tech.technique_id ? 'var(--bg-card-hover)' : '' }}
                      onClick={() => selectTech(tech)}>
                      <td><span className="tech-id">{tech.technique_id}</span></td>
                      <td style={{ color: 'var(--text-primary)' }}>{tech.name}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{tech.tactic}</td>
                      <td style={{ fontFamily: 'var(--mono)', color: tech.alert_count > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>
                        {tech.alert_count > 0 ? `⚠ ${tech.alert_count}` : '—'}
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {(tech.platforms ?? []).slice(0, 3).join(', ')}
                      </td>
                      <td style={{ fontSize: 11, color: tech.is_subtechnique ? 'var(--accent2)' : 'var(--text-muted)' }}>
                        {tech.is_subtechnique ? 'Sub' : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Technique detail panel */}
        {selected && (
          <div className="detail-panel" style={{ width: 320, flexShrink: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span className="tech-id" style={{ fontSize: 15 }}>{selected.technique_id}</span>
              <button className="btn btn-secondary btn-sm" onClick={() => { setSelected(null); setTechDetail(null) }}>✕</button>
            </div>

            <div style={{ fontWeight: 700, fontSize: 14, color: 'var(--text-primary)', marginBottom: 10 }}>{selected.name}</div>

            <div className="detail-row"><span className="detail-key">Tactic</span><span className="detail-val">{selected.tactic}</span></div>
            <div className="detail-row"><span className="detail-key">Tactic ID</span><span className="detail-val tech-id">{selected.tactic_id}</span></div>
            <div className="detail-row">
              <span className="detail-key">Alerts</span>
              <span className="detail-val" style={{ color: selected.alert_count > 0 ? 'var(--critical)' : 'var(--success)' }}>
                {selected.alert_count > 0 ? `⚠ ${selected.alert_count}` : '✓ None'}
              </span>
            </div>
            <div className="detail-row">
              <span className="detail-key">Sub-technique</span>
              <span className="detail-val">{selected.is_subtechnique ? 'Yes' : 'No'}</span>
            </div>

            {Object.entries(selected.severity_distribution ?? {}).map(([sev, cnt]) => (
              <div key={sev} className="detail-row">
                <span className="detail-key">{sev}</span>
                <span className="detail-val" style={{ color: 'var(--text-secondary)' }}>{cnt as number}</span>
              </div>
            ))}

            <div style={{ marginTop: 10, marginBottom: 6, fontSize: 11, color: 'var(--text-muted)' }}>Description</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', background: 'var(--bg-secondary)', padding: 10, borderRadius: 6, lineHeight: 1.6, marginBottom: 10 }}>
              {selected.description || 'No description available.'}
            </div>

            {((techDetail?.platforms as string[] | undefined) ?? []).length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Platforms</div>
                <div>{((techDetail?.platforms ?? selected.platforms ?? []) as string[]).map(p => (
                  <span key={p} className="tag">{p}</span>
                ))}</div>
              </div>
            )}

            {((techDetail?.alerts as unknown[] | undefined) ?? []).length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Related Alerts</div>
                {(techDetail!.alerts as Record<string, string>[]).slice(0, 5).map(a => (
                  <div key={a.alert_id} style={{ padding: '5px 0', borderBottom: '1px solid var(--border)', fontSize: 11 }}>
                    <div style={{ color: 'var(--text-primary)' }}>{a.title}</div>
                    <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                      {a.src_ip} → {a.dst_ip}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <a href={`https://attack.mitre.org/techniques/${selected.technique_id.replace('.', '/')}`}
              target="_blank" rel="noopener noreferrer"
              className="btn btn-secondary btn-sm"
              style={{ width: '100%', justifyContent: 'center', marginTop: 4 }}>
              View on MITRE ATT&CK ↗
            </a>
          </div>
        )}
      </div>
    </div>
  )
}
