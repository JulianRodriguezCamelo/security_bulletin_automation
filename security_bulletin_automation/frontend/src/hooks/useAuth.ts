import { useEffect, useState } from 'react'
import { api } from '../lib/api'

export function useAuth() {
  const [user, setUser]       = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.auth.me()
      .then(r => setUser(r.authenticated ? (r.username ?? null) : null))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  const logout = async () => {
    await api.auth.logout()
    setUser(null)
  }

  return { user, loading, setUser, logout }
}
