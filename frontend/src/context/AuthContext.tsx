import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'
import { authApi } from '../api/client'
import { reconnectWebSocket } from '../hooks/useWebSocket'
import type { User } from '../types'

interface AuthCtx {
  user: User | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const Ctx = createContext<AuthCtx>(null!)
export const useAuth = () => useContext(Ctx)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('soc_token')
    if (!token) { setLoading(false); return }
    authApi.me()
      .then(u => { setUser(u); setLoading(false) })
      .catch(() => { localStorage.removeItem('soc_token'); setLoading(false) })
  }, [])

  const login = async (username: string, password: string) => {
    const data = await authApi.login(username, password)
    localStorage.setItem('soc_token', data.access_token)
    setUser(data.user)
    reconnectWebSocket() // reconnect WS with new token
  }

  const logout = () => {
    localStorage.removeItem('soc_token')
    setUser(null)
    reconnectWebSocket()
  }

  return <Ctx.Provider value={{ user, loading, login, logout }}>{children}</Ctx.Provider>
}
