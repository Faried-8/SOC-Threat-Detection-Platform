import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { Layout } from './components/Layout'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { AlertsPage } from './pages/AlertsPage'
import { IOCsPage } from './pages/IOCsPage'
import { MitrePage } from './pages/MitrePage'
import { SimulationPage } from './pages/SimulationPage'
import { ReportsPage } from './pages/ReportsPage'
import { PCAPPage } from './pages/PCAPPage'
import { Loading } from './components/ui'

function RequireAuth({ children }: { children: JSX.Element }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="login-page"><Loading label="Authenticating..." /></div>
  if (!user) return <Navigate to="/login" replace />
  return children
}

function AppRoutes() {
  const { user } = useAuth()
  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route path="/" element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<DashboardPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="iocs" element={<IOCsPage />} />
        <Route path="mitre" element={<MitrePage />} />
        <Route path="simulation" element={<SimulationPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="pcap" element={<PCAPPage />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return <AuthProvider><AppRoutes /></AuthProvider>
}
