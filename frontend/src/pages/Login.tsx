import { type FormEvent, useState } from 'react'
import { api } from '../lib/api'

interface Props { onLogin: (username: string) => void }

export default function Login({ onLogin }: Props) {
  const [step, setStep]       = useState<'password' | 'totp_setup' | 'totp'>('password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode]       = useState('')
  const [qr, setQr]           = useState('')
  const [error, setError]     = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await api.auth.login(username, password)
      if (res.step === 'totp_setup') {
        setQr(res.qr ?? '')
        setStep('totp_setup')
      } else if (res.step === 'totp') {
        setStep('totp')
      } else {
        onLogin(username)
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Error al iniciar sesión')
    } finally {
      setLoading(false)
    }
  }

  const handleTotp = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await api.auth.verifyTotp(code)
      if (res.step === 'done') onLogin(res.username ?? username)
      else setError('Código incorrecto')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Código incorrecto')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-brand-900 to-brand-950 border border-orange-400/30 flex items-center justify-center text-4xl shadow-card mb-4">
            🛡️
          </div>
          <h1 className="text-2xl font-extrabold text-[#1C0A0F] tracking-widest">ARGOS</h1>
          <p className="text-xs text-[#A07080] mt-1">Inteligencia de Vulnerabilidades</p>
        </div>

        <div className="card p-8">
          {step === 'password' && (
            <>
              <h2 className="text-base font-bold text-[#1C0A0F] mb-5">Iniciar sesión</h2>
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-[#8A5060] uppercase tracking-wide mb-1.5">
                    Usuario
                  </label>
                  <input className="input" value={username} onChange={e => setUsername(e.target.value)} placeholder="usuario" required autoFocus />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#8A5060] uppercase tracking-wide mb-1.5">
                    Contraseña
                  </label>
                  <input className="input" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" required />
                </div>
                {error && <p className="text-xs text-red-600 font-medium">{error}</p>}
                <button className="btn-primary w-full" disabled={loading}>
                  {loading ? 'Verificando…' : 'Continuar →'}
                </button>
              </form>
            </>
          )}

          {step === 'totp_setup' && (
            <>
              <h2 className="text-base font-bold text-[#1C0A0F] mb-2">Configurar 2FA</h2>
              <p className="text-xs text-[#A07080] mb-4">Escanea el QR con tu app de autenticación (Google Authenticator, Authy…)</p>
              {qr && (
                <div className="flex justify-center mb-4">
                  <img src={`data:image/png;base64,${qr}`} alt="QR TOTP" className="w-44 h-44 rounded-xl border border-brand-300 shadow-sm" />
                </div>
              )}
              <form onSubmit={handleTotp} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-[#8A5060] uppercase tracking-wide mb-1.5">
                    Código de verificación
                  </label>
                  <input className="input text-center tracking-widest text-lg" value={code} onChange={e => setCode(e.target.value)} placeholder="000 000" maxLength={6} required autoFocus />
                </div>
                {error && <p className="text-xs text-red-600 font-medium">{error}</p>}
                <button className="btn-primary w-full" disabled={loading}>
                  {loading ? 'Verificando…' : 'Activar y entrar'}
                </button>
              </form>
            </>
          )}

          {step === 'totp' && (
            <>
              <h2 className="text-base font-bold text-[#1C0A0F] mb-2">Verificación 2FA</h2>
              <p className="text-xs text-[#A07080] mb-4">Ingresa el código de tu aplicación de autenticación</p>
              <form onSubmit={handleTotp} className="space-y-4">
                <input className="input text-center tracking-widest text-lg" value={code} onChange={e => setCode(e.target.value)} placeholder="000 000" maxLength={6} required autoFocus />
                {error && <p className="text-xs text-red-600 font-medium">{error}</p>}
                <button className="btn-primary w-full" disabled={loading}>
                  {loading ? 'Verificando…' : '→ Ingresar'}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
