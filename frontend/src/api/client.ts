import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL ?? ''

export const api = axios.create({ baseURL: BASE, timeout: 30000 })

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('soc_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('soc_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// Auth
export const authApi = {
  login: (username: string, password: string) =>
    api.post('/api/auth/login', { username, password }).then(r => r.data),
  me: () => api.get('/api/auth/me').then(r => r.data),
}

// Alerts
export const alertsApi = {
  list: (p?: { severity?: string; category?: string; status?: string; search?: string; limit?: number; offset?: number }) =>
    api.get('/api/alerts/', { params: p }).then(r => r.data),
  stats: () => api.get('/api/alerts/stats').then(r => r.data),
  get: (id: string) => api.get(`/api/alerts/${id}`).then(r => r.data),
  updateStatus: (id: string, body: { status?: string; analyst_notes?: string; is_false_positive?: boolean }) =>
    api.patch(`/api/alerts/${id}/status`, body).then(r => r.data),
}

// IOCs
export const iocsApi = {
  list: (p?: { ioc_type?: string; severity?: string; confidence?: string; search?: string; limit?: number; offset?: number }) =>
    api.get('/api/iocs/', { params: p }).then(r => r.data),
  stats: () => api.get('/api/iocs/stats').then(r => r.data),
  exportCSVUrl: () => `${BASE}/api/iocs/export/csv`,
  exportSTIXUrl: () => `${BASE}/api/iocs/export/stix`,
}

// MITRE
export const mitreApi = {
  matrix: () => api.get('/api/mitre/matrix').then(r => r.data),
  techniques: () => api.get('/api/mitre/techniques').then(r => r.data),
  technique: (id: string) => api.get(`/api/mitre/technique/${id}`).then(r => r.data),
  cacheInfo: () => api.get('/api/mitre/cache-info').then(r => r.data),
  refresh: () => api.post('/api/mitre/refresh').then(r => r.data),
}

// Traffic
export const trafficApi = {
  overview: () => api.get('/api/traffic/overview').then(r => r.data),
  profile: () => api.get('/api/traffic/profile').then(r => r.data),
}

// Simulation
export const simulationApi = {
  scenarios: () => api.get('/api/simulation/scenarios').then(r => r.data),
  start: (scenario: string, speed = 'normal') =>
    api.post('/api/simulation/start', null, { params: { scenario, speed } }).then(r => r.data),
}

// Reports
export const reportsApi = {
  summary: () => api.get('/api/reports/summary').then(r => r.data),
  incidents: () => api.get('/api/reports/incidents').then(r => r.data),
}

// Artifacts
export const artifactsApi = {
  list: () => api.get('/api/artifacts/').then(r => r.data),
  view: (f: string) => api.get(`/api/artifacts/view/${f}`).then(r => r.data),
  downloadUrl: (f: string) => `${BASE}/api/artifacts/download/${f}`,
}

// PCAP
export const pcapApi = {
  upload: (file: File, analyst = 'SOC Analyst') => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('analyst_name', analyst)
    return api.post('/api/pcap/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }).then(r => r.data)
  },
  sessions: () => api.get('/api/pcap/sessions').then(r => r.data),
  session: (id: string) => api.get(`/api/pcap/session/${id}`).then(r => r.data),
}

// Health
export const healthApi = {
  check: () => api.get('/api/health').then(r => r.data),
}
