import { useEffect, useState } from 'react'
import { api } from '../lib/api'

type ConfigData = {
  keys: Record<string, { severity: string; set: boolean; masked: string }>
  groq_model: string
  company_techs: string
  report_to: string
}

const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'text-red-600 bg-red-50 border-red-300',
  HIGH:     'text-brand-500 bg-brand-50 border-brand-300',
  MEDIUM:   'text-amber-600 bg-amber-50 border-amber-300',
  LOW:      'text-blue-600 bg-blue-50 border-blue-300',
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

export default function Config() {
  const [cfg, setCfg]     = useState<ConfigData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.config.get().then(setCfg).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="text-sm text-[#A07080]">Cargando configuración…</div>
  if (!cfg)    return <div className="text-sm text-red-600">Error cargando configuración</div>

  return (
    <div className="max-w-2xl space-y-5">
      <div className="mb-2">
        <h1 className="text-2xl font-extrabold text-[#1C0A0F] flex items-center gap-2">
          <span>⚙️</span> Configuración
        </h1>
      </div>

      {/* API Status */}
      <Section icon="🖥️" title="Conexión Backend">
        <div className="flex items-center gap-2.5 bg-green-50 border border-green-200 rounded-xl px-4 py-3">
          <span className="w-2 h-2 rounded-full bg-green-400 shadow-[0_0_6px_rgba(74,222,128,0.6)] shrink-0" />
          <span className="text-sm font-semibold text-green-700">Backend: Conectado</span>
          <span className="text-xs text-[#A07080] ml-1">http://localhost:5000</span>
        </div>
      </Section>

      {/* AI Model */}
      <Section icon="⚡" title="Modelo de IA (Groq)">
        <div className="flex items-center gap-3 bg-gradient-to-r from-brand-500/5 to-orange-500/5 border border-brand-500/15 rounded-xl px-4 py-3">
          <span className="text-xl">🤖</span>
          <span className="text-sm font-semibold text-[#1C0A0F]">{cfg.groq_model}</span>
        </div>
        <p className="text-xs text-[#B09AA5]">
          Configurado en <code className="bg-brand-50 text-[#8A5060] px-1.5 py-0.5 rounded">ai_analyzer.py</code> via{' '}
          <code className="bg-brand-50 text-[#8A5060] px-1.5 py-0.5 rounded">GROQ_API_KEY</code> en el <code className="bg-brand-50 text-[#8A5060] px-1.5 py-0.5 rounded">.env</code>
        </p>
        <p className="text-[11px] font-bold text-[#8A5060] uppercase tracking-wide">API Keys</p>
        <div className="border border-brand-300 rounded-xl overflow-hidden">
          {Object.entries(cfg.keys).map(([k, v], i, arr) => (
            <div key={k} className={`flex items-center gap-3 px-4 py-3 ${i < arr.length - 1 ? 'border-b border-brand-300/60' : ''}`}>
              <span className={`badge border text-[10px] ${SEV_BADGE[v.severity] ?? ''}`}>{v.severity}</span>
              <code className="text-xs text-[#8A5060] flex-1 font-mono">
                {k}
                {v.masked && <span className="text-[#C4A8B2]"> = {v.masked}</span>}
              </code>
              <span className={`text-base font-bold ${v.set ? 'text-green-500' : 'text-red-500'}`}>
                {v.set ? '✓' : '✗'}
              </span>
            </div>
          ))}
        </div>
        <p className="text-xs text-[#C4A8B2]">
          Para cambiar las keys, edita <code className="bg-brand-50 text-[#8A5060] px-1.5 py-0.5 rounded">.env</code> en la raíz del proyecto.
        </p>
      </Section>

      {/* Preferences */}
      <Section icon="⚙️" title="Preferencias">
        <div className="space-y-3">
          <div>
            <p className="text-xs font-semibold text-[#8A5060] uppercase tracking-wide mb-1.5">Tecnologías de la empresa</p>
            <input
              className="input text-sm"
              value={cfg.company_techs}
              disabled
              placeholder="No configuradas — edita .env"
            />
            <p className="text-xs text-[#C4A8B2] mt-1">Edita COMPANY_TECHS en el archivo .env</p>
          </div>
        </div>
      </Section>

      {/* Email */}
      <Section icon="📧" title="Entrega de Informes">
        <div className="flex items-center gap-2.5">
          <span className={`w-2 h-2 rounded-full shrink-0 ${cfg.report_to ? 'bg-green-400' : 'bg-brand-300'}`} />
          <span className="text-xs text-[#8A5060]">Destinatario:</span>
          <span className="text-xs font-semibold text-[#1C0A0F]">{cfg.report_to || 'No configurado'}</span>
        </div>
      </Section>
    </div>
  )
}
