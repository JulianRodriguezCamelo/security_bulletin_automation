const BASE = '/api'

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'include',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (res.status === 401 && path !== '/auth/login' && path !== '/auth/me') {
    window.dispatchEvent(new CustomEvent('session-expired'))
    throw new Error('Sesión expirada')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error ?? res.statusText)
  }
  return res.json()
}

export const api = {
  auth: {
    me:         ()                              => req<{ authenticated: boolean; username?: string; role?: string }>('GET', '/auth/me'),
    login:      (username: string, pw: string) => req<{ step: string; qr?: string; secret?: string; role?: string; error?: string }>('POST', '/auth/login', { username, password: pw }),
    verifyTotp: (code: string)                 => req<{ step: string; username?: string; role?: string; error?: string }>('POST', '/auth/totp/verify', { code }),
    logout:     ()                             => req<{ ok: boolean }>('POST', '/auth/logout'),
  },

  files: {
    list:   ()           => req<{ name: string; size: number }[]>('GET', '/files'),
    remove: (name: string) => req<{ ok: boolean }>('DELETE', `/files/${encodeURIComponent(name)}`),
    upload: (files: File[]) => {
      const fd = new FormData()
      files.forEach(f => fd.append('files', f))
      return fetch(`${BASE}/files`, { method: 'POST', credentials: 'include', body: fd }).then(r => r.json())
    },
  },

  process: () => new EventSource(`${BASE}/process`, { withCredentials: true }),

  archive: {
    getThreats:  ()                                          => req<Record<string, unknown>[]>('GET', '/archive/threats'),
    getIocs:     ()                                          => req<Record<string, unknown>[]>('GET', '/archive/iocs'),
    save:        (threats: unknown[], iocs: unknown[])       => req<{ ok: boolean }>('POST', '/archive/save', { threats, iocs }),
    migrate:     ()                                          => req<{ ok: boolean }>('POST', '/archive/migrate'),
    downloadUrl: ()                                          => `${BASE}/archive/download`,
  },

  alerts: {
    get: () => req<Record<string, unknown>[]>('GET', '/alerts'),
  },

  config: {
    get: () => req<{
      keys: Record<string, { severity: string; set: boolean; masked: string }>
      groq_model: string
      company_techs: string
      report_to: string
    }>('GET', '/config'),
  },
}
