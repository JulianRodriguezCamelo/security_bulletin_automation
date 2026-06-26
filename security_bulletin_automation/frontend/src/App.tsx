import { useEffect, useRef, useState } from 'react'
import { api } from './lib/api'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Upload from './pages/Upload'
import Archive from './pages/Archive'
import Config from './pages/Config'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'

type Page = 'dashboard' | 'upload' | 'archive' | 'config'

const IDLE_MS = 20 * 60 * 1000

export default function App() {
  const [user, setUser]       = useState<string | null>(null)
  const [role, setRole]       = useState<string>('user')
  const [loading, setLoading] = useState(true)
  const [page, setPage]       = useState<Page>('dashboard')
  const [pending, setPending] = useState(0)
  const idleTimer             = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    api.auth.me()
      .then(r => {
        if (r.authenticated) {
          setUser(r.username ?? '')
          setRole(r.role ?? 'user')
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  // Cierra sesión tras 20 minutos de inactividad
  useEffect(() => {
    if (!user) return

    const doLogout = async () => {
      await api.auth.logout().catch(() => {})
      setUser(null)
      setRole('user')
    }

    const reset = () => {
      if (idleTimer.current) clearTimeout(idleTimer.current)
      idleTimer.current = setTimeout(doLogout, IDLE_MS)
    }

    const events = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'] as const
    events.forEach(e => window.addEventListener(e, reset, { passive: true }))
    reset()

    return () => {
      if (idleTimer.current) clearTimeout(idleTimer.current)
      events.forEach(e => window.removeEventListener(e, reset))
    }
  }, [user])

  // El backend también puede expirar la sesión (401) — escucha el evento global
  useEffect(() => {
    const handler = () => { setUser(null); setRole('user') }
    window.addEventListener('session-expired', handler)
    return () => window.removeEventListener('session-expired', handler)
  }, [])

  useEffect(() => {
    if (!user) return
    const refresh = () => api.files.list().then(f => setPending(f.length)).catch(() => {})
    refresh()
    const id = setInterval(refresh, 10_000)
    return () => clearInterval(id)
  }, [user])

  // Si cambia de rol y estaba en Config, volver al Dashboard
  useEffect(() => {
    if (page === 'config' && role !== 'admin') setPage('dashboard')
  }, [role, page])

  const logout = async () => {
    await api.auth.logout()
    setUser(null)
    setRole('user')
  }

  const handleSetPage = (p: Page) => {
    if (p === 'config' && role !== 'admin') return
    setPage(p)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <div className="text-brand-500 text-4xl animate-pulse">🛡️</div>
      </div>
    )
  }

  if (!user) {
    return <Login onLogin={(u, r) => { setUser(u); setRole(r ?? 'user'); setPage('dashboard') }} />
  }

  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Navbar page={page} setPage={handleSetPage} user={user} role={role} onLogout={logout} pending={pending} />
        <main className="flex-1 overflow-y-auto px-6 py-7">
          {page === 'dashboard' && <Dashboard />}
          {page === 'upload'    && <Upload />}
          {page === 'archive'   && <Archive />}
          {page === 'config'    && role === 'admin' && <Config />}
          {page === 'config'    && role !== 'admin' && (
            <div className="flex items-center justify-center h-full text-[#A07080] text-sm">
              Acceso restringido — se requieren permisos de administrador.
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
