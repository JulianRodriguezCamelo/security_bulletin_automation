import { useEffect, useState } from 'react'
import { api } from './lib/api'
import Login from './pages/Login'
import Upload from './pages/Upload'
import Archive from './pages/Archive'
import Config from './pages/Config'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'

type Page = 'upload' | 'archive' | 'config'

export default function App() {
  const [user, setUser]       = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage]       = useState<Page>('archive')
  const [pending, setPending] = useState(0)

  useEffect(() => {
    api.auth.me()
      .then(r => { if (r.authenticated) setUser(r.username ?? '') })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!user) return
    const refresh = () => api.files.list().then(f => setPending(f.length)).catch(() => {})
    refresh()
    const id = setInterval(refresh, 10_000)
    return () => clearInterval(id)
  }, [user])

  const logout = async () => {
    await api.auth.logout()
    setUser(null)
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <div className="text-brand-500 text-4xl animate-pulse">🛡️</div>
      </div>
    )
  }

  if (!user) {
    return <Login onLogin={u => { setUser(u); setPage('archive') }} />
  }

  return (
    <div className="flex h-screen overflow-hidden bg-bg">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Navbar page={page} setPage={setPage} user={user} onLogout={logout} pending={pending} />
        <main className="flex-1 overflow-y-auto px-6 py-7">
          <div className={page !== 'upload' ? 'hidden' : undefined}>
            <Upload />
          </div>
          {page === 'archive' && <Archive />}
          {page === 'config'  && <Config />}
        </main>
      </div>
    </div>
  )
}
