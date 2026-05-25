import { useEffect, useRef, useState, useCallback } from 'react'
import type { WSMessage } from '../types'

type Handler = (msg: WSMessage) => void

// Global singleton WebSocket so all hooks share one connection
let globalWS: WebSocket | null = null
const globalHandlers: Set<Handler> = new Set()
let globalStatus: 'connecting' | 'connected' | 'disconnected' | 'error' = 'disconnected'
const statusListeners: Set<(s: typeof globalStatus) => void> = new Set()
let reconnectTimer: ReturnType<typeof setTimeout> | null = null

function notifyStatus(s: typeof globalStatus) {
  globalStatus = s
  statusListeners.forEach(l => l(s))
}

function connectGlobal() {
  if (globalWS && (globalWS.readyState === WebSocket.OPEN || globalWS.readyState === WebSocket.CONNECTING)) return
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null }

  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const host = window.location.host
  const token = localStorage.getItem('soc_token') ?? ''
  const url = `${proto}://${host}/ws${token ? `?token=${token}` : ''}`

  notifyStatus('connecting')
  const socket = new WebSocket(url)
  globalWS = socket

  socket.onopen = () => {
    notifyStatus('connected')
    // Send ping every 30s to keep alive
    const ping = setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) socket.send('ping')
      else clearInterval(ping)
    }, 30000)
  }

  socket.onclose = () => {
    globalWS = null
    notifyStatus('disconnected')
    reconnectTimer = setTimeout(connectGlobal, 4000)
  }

  socket.onerror = () => {
    notifyStatus('error')
    socket.close()
  }

  socket.onmessage = (e) => {
    try {
      const msg: WSMessage = JSON.parse(e.data)
      globalHandlers.forEach(h => {
        try { h(msg) } catch { /* ignore handler errors */ }
      })
    } catch { /* ignore parse errors */ }
  }
}

export function useWebSocket(onMessage?: Handler) {
  const [status, setStatus] = useState<typeof globalStatus>(globalStatus)
  const handlerRef = useRef<Handler | undefined>(onMessage)
  handlerRef.current = onMessage

  useEffect(() => {
    // Stable wrapper so we can remove it cleanly
    const handler: Handler = (msg) => handlerRef.current?.(msg)
    if (onMessage) globalHandlers.add(handler)

    const statusListener = (s: typeof globalStatus) => setStatus(s)
    statusListeners.add(statusListener)
    setStatus(globalStatus)

    // Start connection if not already running
    connectGlobal()

    return () => {
      if (onMessage) globalHandlers.delete(handler)
      statusListeners.delete(statusListener)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return { status }
}

// Reconnect with fresh token after login
export function reconnectWebSocket() {
  if (globalWS) { globalWS.close(); globalWS = null }
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null }
  setTimeout(connectGlobal, 300)
}
