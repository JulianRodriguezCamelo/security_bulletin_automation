import { useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'

type User = { username: string; role: string; has_totp: boolean }

type ModalState =
  | { type: 'none' }
  | { type: 'create' }
  | { type: 'qr'; username: string; qr: string; secret: string }
  | { type: 'confirm_delete'; username: string }
  | { type: 'confirm_reset'; username: string }

const ROLE_BADGE: Record<string, string> = {
  admin: 'text-brand-500 bg-brand-50 border-brand-300',
  user:  'text-blue-600 bg-blue-50 border-blue-200',
}

function Section({ icon, title, children }: { icon: string; title: string; children: React.ReactNode }) {
  return (
    <div className="card p-6 space-y-4">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-500/10 to-orange-500/10 border border-brand-500/20 flex items-center justify-center text-base">
          {icon}
        </div>
        <span className="text-base font-bold text-[#1C0A0F]">{title}</span>
      </div>
      {children}
    </div>
  )
}

function PasswordStrength({ password }: { password: string }) {
  const checks = [
    { ok: password.length >= 8,          label: '≥8 caracteres'   },
    { ok: /[A-Z]/.test(password),        label: 'Mayúscula'       },
    { ok: /[a-z]/.test(password),        label: 'Minúscula'       },
    { ok: /[0-9]/.test(password),        label: 'Número'          },
    { ok: /[^A-Za-z0-9]/.test(password), label: 'Carácter especial' },
  ]
  const score = checks.filter(c => c.ok).length

  const bar = score <= 1 ? 'bg-red-400' : score <= 3 ? 'bg-amber-400' : 'bg-green-400'
  const label = score <= 1 ? 'Muy débil' : score <= 3 ? 'Moderada' : 'Fuerte'

  return (
    <div className="space-y-1.5 mt-1">
      <div className="flex gap-1 h-1">
        {[1, 2, 3, 4, 5].map(i => (
          <div
            key={i}
            className={`flex-1 rounded-full transition-colors ${i <= score ? bar : 'bg-brand-200'}`}
          />
        ))}
      </div>
      <div className="flex items-center justify-between">
        <span className={`text-[10px] font-semibold ${score <= 1 ? 'text-red-500' : score <= 3 ? 'text-amber-500' : 'text-green-600'}`}>
          {password.length > 0 ? label : ''}
        </span>
        <div className="flex gap-2 flex-wrap justify-end">
          {checks.map(c => (
            <span
              key={c.label}
              className={`text-[9px] font-medium ${c.ok ? 'text-green-600' : 'text-[#C4A8B2]'}`}
            >
              {c.ok ? '✓' : '○'} {c.label}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

function CreateUserModal({
  onClose,
  onCreate,
}: {
  onClose: () => void
  onCreate: (username: string, password: string, role: string) => Promise<void>
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw]     = useState(false)
  const [role, setRole]         = useState<'user' | 'admin'>('user')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const usernameRef             = useRef<HTMLInputElement>(null)

  useEffect(() => { usernameRef.current?.focus() }, [])

  const valid = username.trim().length >= 2 && password.length >= 8

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!valid) return
    setLoading(true)
    setError('')
    try {
      await onCreate(username.trim(), password, role)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Error al crear usuario')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm px-4">
      <div className="bg-white rounded-2xl shadow-2xl border border-brand-200 w-full max-w-md p-6 space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-500/10 to-orange-500/10 border border-brand-500/20 flex items-center justify-center text-base">
              👤
            </div>
            <span className="text-base font-bold text-[#1C0A0F]">Nuevo Usuario</span>
          </div>
          <button onClick={onClose} className="text-[#A07080] hover:text-brand-500 text-xl leading-none transition-colors">
            ✕
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          {/* Username */}
          <div>
            <label className="text-xs font-semibold text-[#8A5060] uppercase tracking-wide block mb-1.5">
              Nombre de usuario
            </label>
            <input
              ref={usernameRef}
              value={username}
              onChange={e => setUsername(e.target.value)}
              className="input text-sm w-full"
              placeholder="ej: jrodriguez"
              autoComplete="off"
              spellCheck={false}
            />
          </div>

          {/* Password */}
          <div>
            <label className="text-xs font-semibold text-[#8A5060] uppercase tracking-wide block mb-1.5">
              Contraseña
            </label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="input text-sm w-full pr-10"
                placeholder="Mínimo 8 caracteres"
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => setShowPw(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[#A07080] hover:text-brand-500 text-xs transition-colors"
              >
                {showPw ? '🙈' : '👁️'}
              </button>
            </div>
            {password && <PasswordStrength password={password} />}
          </div>

          {/* Role */}
          <div>
            <label className="text-xs font-semibold text-[#8A5060] uppercase tracking-wide block mb-1.5">
              Rol
            </label>
            <div className="flex gap-2">
              {(['user', 'admin'] as const).map(r => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setRole(r)}
                  className={[
                    'flex-1 py-2 rounded-xl border text-sm font-semibold transition-all',
                    role === r
                      ? r === 'admin'
                        ? 'bg-brand-50 border-brand-400 text-brand-600'
                        : 'bg-blue-50 border-blue-300 text-blue-700'
                      : 'border-brand-200 text-[#A07080] hover:border-brand-300',
                  ].join(' ')}
                >
                  {r === 'admin' ? '🔑 Admin' : '👤 Usuario'}
                </button>
              ))}
            </div>
            {role === 'admin' && (
              <p className="text-[10px] text-amber-600 mt-1.5 flex items-center gap-1">
                ⚠️ Los administradores tienen acceso total al sistema.
              </p>
            )}
          </div>

          {/* 2FA info */}
          <div className="flex items-start gap-2.5 bg-blue-50 border border-blue-200 rounded-xl px-4 py-3">
            <span className="text-base mt-0.5">📱</span>
            <div>
              <p className="text-xs font-semibold text-blue-700">Autenticación de dos pasos (TOTP)</p>
              <p className="text-[11px] text-blue-600 mt-0.5 leading-relaxed">
                Al iniciar sesión por primera vez, el usuario escaneará un código QR con <strong>Microsoft Authenticator</strong> para activar 2FA.
              </p>
            </div>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-xl px-4 py-3 text-sm text-red-700 flex items-center gap-2">
              <span>⚠️</span> {error}
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 py-2.5 rounded-xl border border-brand-300 text-sm font-semibold text-[#A07080] hover:border-brand-400 transition-all"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={!valid || loading}
              className="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-brand-500 to-brand-600 text-white text-sm font-bold shadow-sm hover:from-brand-600 hover:to-brand-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {loading ? 'Creando…' : 'Crear usuario'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function QrModal({ username, qr, secret, onClose }: { username: string; qr: string; secret: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(secret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm px-4">
      <div className="bg-white rounded-2xl shadow-2xl border border-brand-200 w-full max-w-sm p-6 space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="text-xl">📱</span>
            <span className="text-base font-bold text-[#1C0A0F]">Configurar 2FA</span>
          </div>
          <button onClick={onClose} className="text-[#A07080] hover:text-brand-500 text-xl leading-none transition-colors">
            ✕
          </button>
        </div>

        <div className="space-y-1">
          <p className="text-sm font-semibold text-[#1C0A0F]">Usuario: <span className="text-brand-500">{username}</span></p>
          <p className="text-xs text-[#A07080] leading-relaxed">
            Escanea este QR con <strong>Microsoft Authenticator</strong> (o cualquier app TOTP como Google Authenticator).
          </p>
        </div>

        <div className="flex justify-center">
          <div className="p-3 rounded-2xl border-2 border-brand-200 bg-white shadow-inner">
            <img src={`data:image/png;base64,${qr}`} alt="QR 2FA" className="w-44 h-44" />
          </div>
        </div>

        <div className="space-y-2">
          <p className="text-[10px] text-[#A07080] uppercase tracking-wide font-semibold">Clave manual (si no puedes escanear)</p>
          <div className="flex items-center gap-2 bg-brand-50 border border-brand-200 rounded-xl px-3 py-2">
            <code className="text-xs text-[#8A5060] font-mono flex-1 break-all">{secret}</code>
            <button
              onClick={copy}
              className="text-[10px] font-bold text-brand-500 hover:text-brand-700 whitespace-nowrap transition-colors"
            >
              {copied ? '✓ Copiado' : 'Copiar'}
            </button>
          </div>
        </div>

        <div className="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 text-xs text-amber-700 leading-relaxed">
          <strong>Importante:</strong> Guarda esta clave en un lugar seguro. Si el usuario pierde acceso a su autenticador, un administrador puede resetear el 2FA desde esta pantalla.
        </div>

        <button
          onClick={onClose}
          className="w-full py-2.5 rounded-xl bg-gradient-to-r from-brand-500 to-brand-600 text-white text-sm font-bold shadow-sm hover:from-brand-600 hover:to-brand-700 transition-all"
        >
          Listo
        </button>
      </div>
    </div>
  )
}

function ConfirmModal({
  title,
  message,
  confirmLabel,
  danger,
  onConfirm,
  onClose,
}: {
  title: string
  message: string
  confirmLabel: string
  danger?: boolean
  onConfirm: () => Promise<void>
  onClose: () => void
}) {
  const [loading, setLoading] = useState(false)

  const handle = async () => {
    setLoading(true)
    try { await onConfirm() } finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm px-4">
      <div className="bg-white rounded-2xl shadow-2xl border border-brand-200 w-full max-w-sm p-6 space-y-4">
        <p className="text-base font-bold text-[#1C0A0F]">{title}</p>
        <p className="text-sm text-[#8A5060] leading-relaxed">{message}</p>
        <div className="flex gap-2 pt-1">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl border border-brand-300 text-sm font-semibold text-[#A07080] hover:border-brand-400 transition-all"
          >
            Cancelar
          </button>
          <button
            onClick={handle}
            disabled={loading}
            className={[
              'flex-1 py-2.5 rounded-xl text-white text-sm font-bold shadow-sm disabled:opacity-40 transition-all',
              danger
                ? 'bg-red-500 hover:bg-red-600'
                : 'bg-gradient-to-r from-brand-500 to-brand-600 hover:from-brand-600 hover:to-brand-700',
            ].join(' ')}
          >
            {loading ? 'Procesando…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Users() {
  const [users, setUsers]   = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [modal, setModal]   = useState<ModalState>({ type: 'none' })
  const [toast, setToast]   = useState('')

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(''), 3500)
  }

  const refresh = () =>
    api.users.list()
      .then(setUsers)
      .catch(() => {})
      .finally(() => setLoading(false))

  useEffect(() => { refresh() }, [])

  const handleCreate = async (username: string, password: string, role: string) => {
    await api.users.create(username, password, role)
    await refresh()
    setModal({ type: 'none' })
    showToast(`Usuario "${username}" creado correctamente.`)
  }

  const handleDelete = async (username: string) => {
    await api.users.delete(username)
    await refresh()
    setModal({ type: 'none' })
    showToast(`Usuario "${username}" eliminado.`)
  }

  const handleResetTotp = async (username: string) => {
    await api.users.resetTotp(username)
    await refresh()
    setModal({ type: 'none' })
    showToast(`2FA reseteado para "${username}". Configurará el QR en su próximo inicio de sesión.`)
  }

  return (
    <div className="max-w-3xl space-y-5">
      {/* Toast */}
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-green-600 text-white text-sm font-semibold px-5 py-3 rounded-2xl shadow-lg animate-in fade-in">
          ✓ {toast}
        </div>
      )}

      {/* Modals */}
      {modal.type === 'create' && (
        <CreateUserModal
          onClose={() => setModal({ type: 'none' })}
          onCreate={handleCreate}
        />
      )}
      {modal.type === 'qr' && (
        <QrModal
          username={modal.username}
          qr={modal.qr}
          secret={modal.secret}
          onClose={() => setModal({ type: 'none' })}
        />
      )}
      {modal.type === 'confirm_delete' && (
        <ConfirmModal
          title="Eliminar usuario"
          message={`¿Estás seguro de que deseas eliminar al usuario "${modal.username}"? Esta acción no se puede deshacer.`}
          confirmLabel="Eliminar"
          danger
          onConfirm={() => handleDelete(modal.username)}
          onClose={() => setModal({ type: 'none' })}
        />
      )}
      {modal.type === 'confirm_reset' && (
        <ConfirmModal
          title="Resetear autenticación 2FA"
          message={`Se eliminará el secreto TOTP de "${modal.username}". La próxima vez que inicie sesión, deberá escanear un nuevo código QR con Microsoft Authenticator.`}
          confirmLabel="Resetear 2FA"
          onConfirm={() => handleResetTotp(modal.username)}
          onClose={() => setModal({ type: 'none' })}
        />
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-extrabold text-[#1C0A0F] flex items-center gap-2">
          <span>👥</span> Usuarios
        </h1>
        <button
          onClick={() => setModal({ type: 'create' })}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-brand-500 to-brand-600 text-white text-sm font-bold shadow-sm hover:from-brand-600 hover:to-brand-700 transition-all"
        >
          <span>+</span> Nuevo usuario
        </button>
      </div>

      {/* 2FA info banner */}
      <Section icon="📱" title="Autenticación de dos pasos (TOTP)">
        <p className="text-sm text-[#8A5060] leading-relaxed">
          Todos los usuarios deben configurar la autenticación de dos pasos con{' '}
          <strong className="text-[#1C0A0F]">Microsoft Authenticator</strong> la primera vez que inician sesión.
          Los códigos se generan cada <strong className="text-[#1C0A0F]">30 segundos</strong> y son compatibles con cualquier app TOTP (RFC 6238).
        </p>
        <div className="grid grid-cols-3 gap-3 mt-2">
          {[
            { icon: '📲', title: 'Escanea el QR',    desc: 'En el primer login aparece el código QR' },
            { icon: '🔢', title: 'Ingresa el código', desc: 'Código de 6 dígitos que rota cada 30s'    },
            { icon: '✅', title: 'Acceso seguro',     desc: 'Sesión autenticada con 2 factores'        },
          ].map(step => (
            <div key={step.title} className="flex flex-col items-center text-center gap-1.5 bg-brand-50/60 rounded-xl p-3 border border-brand-100">
              <span className="text-2xl">{step.icon}</span>
              <p className="text-[11px] font-bold text-[#1C0A0F]">{step.title}</p>
              <p className="text-[10px] text-[#A07080] leading-relaxed">{step.desc}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* Users table */}
      <Section icon="👥" title="Usuarios del sistema">
        {loading ? (
          <div className="text-sm text-[#A07080] py-4 text-center">Cargando usuarios…</div>
        ) : users.length === 0 ? (
          <div className="text-sm text-[#A07080] py-4 text-center">No hay usuarios registrados.</div>
        ) : (
          <div className="border border-brand-200 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-brand-50 border-b border-brand-200">
                  <th className="px-4 py-3 text-left text-[10px] font-bold text-[#8A5060] uppercase tracking-wider">Usuario</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold text-[#8A5060] uppercase tracking-wider">Rol</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold text-[#8A5060] uppercase tracking-wider">2FA</th>
                  <th className="px-4 py-3 text-right text-[10px] font-bold text-[#8A5060] uppercase tracking-wider">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => (
                  <tr
                    key={u.username}
                    className={`${i < users.length - 1 ? 'border-b border-brand-100' : ''} hover:bg-brand-50/40 transition-colors`}
                  >
                    {/* Username */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center text-xs font-bold text-white shadow-sm shrink-0">
                          {u.username[0]?.toUpperCase()}
                        </div>
                        <span className="font-semibold text-[#1C0A0F]">{u.username}</span>
                      </div>
                    </td>

                    {/* Role */}
                    <td className="px-4 py-3">
                      <span className={`badge border text-[10px] ${ROLE_BADGE[u.role] ?? ''}`}>
                        {u.role === 'admin' ? '🔑 Admin' : '👤 Usuario'}
                      </span>
                    </td>

                    {/* 2FA status */}
                    <td className="px-4 py-3">
                      {u.has_totp ? (
                        <div className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-green-400 shadow-[0_0_5px_rgba(74,222,128,0.6)]" />
                          <span className="text-xs font-semibold text-green-700">Configurado</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-amber-400" />
                          <span className="text-xs font-semibold text-amber-600">Pendiente</span>
                        </div>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        {u.has_totp && (
                          <button
                            onClick={() => setModal({ type: 'confirm_reset', username: u.username })}
                            title="Resetear 2FA"
                            className="text-[11px] font-semibold text-amber-600 border border-amber-200 bg-amber-50 hover:bg-amber-100 px-2.5 py-1 rounded-lg transition-all"
                          >
                            🔄 Reset 2FA
                          </button>
                        )}
                        <button
                          onClick={() => setModal({ type: 'confirm_delete', username: u.username })}
                          title="Eliminar usuario"
                          className="text-[11px] font-semibold text-red-600 border border-red-200 bg-red-50 hover:bg-red-100 px-2.5 py-1 rounded-lg transition-all"
                        >
                          🗑️ Eliminar
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="text-xs text-[#C4A8B2]">
          Total: <strong className="text-[#8A5060]">{users.length}</strong> usuario{users.length !== 1 ? 's' : ''} registrado{users.length !== 1 ? 's' : ''}.
        </p>
      </Section>
    </div>
  )
}
