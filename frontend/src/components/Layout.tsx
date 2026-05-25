import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { useWebSocket } from '../hooks/useWebSocket'
import { useState, useCallback, useEffect } from 'react'
import type { WSMessage } from '../types'

const NAV = [
  { to: '/', label: 'Dashboard', icon: '⬡', exact: true },
  { to: '/alerts', label: 'Alerts', icon: '⚠', badge: true },
  { to: '/iocs', label: 'IOC Management', icon: '◈' },
  { to: '/mitre', label: 'MITRE ATT\u0026CK', icon: '⬢' },
  { to: '/simulation', label: 'Simulation', icon: '▶' },
  { to: '/pcap', label: 'PCAP Analysis', icon: '⬚' },
  { to: '/reports', label: 'Reports', icon: '≡' },
]

export function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const [newAlertCount, setNewAlertCount] = useState(0)

  // Clear badge when user visits alerts page
  useEffect(() => {
    if (location.pathname === '/alerts') setNewAlertCount(0)
  }, [location.pathname])

  const onMessage = useCallback((msg: WSMessage) => {
    if (msg.type === 'new_alert' && location.pathname !== '/alerts') {
      setNewAlertCount(n => n + 1)
    }
  }, [location.pathname])

  const { status } = useWebSocket(onMessage)

  const wsLabel = {
    connected: 'LIVE',
    connecting: 'CONNECTING',
    disconnected: 'OFFLINE',
    error: 'ERROR',
  }[status]

  const wsColor = {
    connected: 'var(--success)',
    connecting: 'var(--medium)',
    disconnected: 'var(--text-muted)',
    error: 'var(--critical)',
  }[status]

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="nav-logo">
          SOC<span style={{ color: 'var(--text-muted)' }}>://</span>PLATFORM
          <small>Enterprise Threat Detection v2.0</small>
        </div>

        <nav style={{ flex: 1, padding: '8px 0' }}>
          <div className="nav-section">
            <div className="nav-section-label">Operations</div>
          </div>
          {NAV.map(({ to, label, icon, exact, badge }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <span>{icon}</span>
              <span style={{ flex: 1 }}>{label}</span>
              {badge && newAlertCount > 0 && (
                <span className="nav-badge">{newAlertCount > 99 ? '99+' : newAlertCount}</span>
              )}
            </NavLink>
          ))}
        </nav>

        <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
            <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>
              {user?.full_name ?? user?.username}
            </span>
            <br />
            <span style={{
              textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: 10,
              background: user?.role === 'admin' ? 'rgba(124,58,237,0.2)' : 'rgba(0,212,255,0.1)',
              color: user?.role === 'admin' ? 'var(--accent2)' : 'var(--accent)',
              padding: '1px 6px', borderRadius: 3, display: 'inline-block', marginTop: 2,
            }}>
              {user?.role}
            </span>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={logout}
            style={{ width: '100%', justifyContent: 'center' }}>
            Sign Out
          </button>
        </div>
      </aside>

      <div className="main-content">
        <header className="topbar">
          {/* WS status indicator */}
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: wsColor,
            boxShadow: status === 'connected' ? `0 0 6px ${wsColor}` : 'none',
            animation: status === 'connected' ? 'wsPulse 2s infinite' : 'none',
            flexShrink: 0,
          }} />
          <span style={{ fontSize: 11, color: wsColor, fontFamily: 'var(--mono)', letterSpacing: '0.05em' }}>
            {wsLabel}
          </span>
          <div style={{ flex: 1 }} />
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
            {new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC
          </span>
        </header>

        <div className="page-body">
          <Outlet />
        </div>
      </div>

      <style>{`
        @keyframes wsPulse { 0%,100%{opacity:1} 50%{opacity:.4} }
      `}</style>
    </div>
  )
}
