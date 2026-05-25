import { useState } from 'react'
import { useAuth } from '../context/AuthContext'

export function LoginPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async () => {
    if (!username || !password) { setErr('Enter credentials'); return }
    setLoading(true); setErr('')
    try { await login(username, password) }
    catch { setErr('Invalid credentials') }
    finally { setLoading(false) }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-title">◈ SOC PLATFORM</div>
        <div className="login-subtitle">Enterprise Network Threat Detection System</div>

        <div className="form-group">
          <label className="form-label">USERNAME</label>
          <input className="input" value={username} onChange={e => setUsername(e.target.value)}
            placeholder="analyst" autoFocus onKeyDown={e => e.key === 'Enter' && submit()} />
        </div>
        <div className="form-group">
          <label className="form-label">PASSWORD</label>
          <input className="input" type="password" value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••" onKeyDown={e => e.key === 'Enter' && submit()} />
        </div>
        {err && <div className="form-error">{err}</div>}
        <button className="btn btn-primary" style={{ width: '100%', marginTop: 20, justifyContent: 'center' }}
          onClick={submit} disabled={loading}>
          {loading ? 'Authenticating...' : '→ AUTHENTICATE'}
        </button>

        <div style={{ marginTop: 20, padding: '12px', background: 'var(--bg-secondary)', borderRadius: 6, fontSize: 11, color: 'var(--text-muted)' }}>
          <strong style={{ color: 'var(--text-secondary)' }}>Demo credentials:</strong><br />
          admin / admin123 &nbsp;|&nbsp; analyst / analyst123
        </div>
      </div>
    </div>
  )
}
