import { useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'

type Threat = Record<string, unknown>

const TYPE_ICON: Record<string, string> = {
  vulnerabilidad:        '🔓',
  malware:               '🦠',
  ransomware:            '💀',
  phishing:              '🎣',
  apt:                   '🎯',
  campaña:               '📡',
  'amenaza/vulnerabilidad': '⚠️',
  amenaza:               '⚠️',
}

function threatIcon(tipo: string) {
  return TYPE_ICON[tipo?.toLowerCase()] ?? '🚨'
}

function severityColor(tipo: string) {
  const t = tipo?.toLowerCase()
  if (t === 'vulnerabilidad' || t === 'amenaza/vulnerabilidad') return 'text-orange-500'
  if (t === 'malware' || t === 'ransomware' || t === 'apt') return 'text-red-500'
  return 'text-yellow-500'
}

const CRITICIDAD_STYLE: Record<string, string> = {
  'crítica':     'bg-red-100 text-red-700 border-red-300',
  'alta':        'bg-orange-100 text-orange-700 border-orange-300',
  'media':       'bg-yellow-100 text-yellow-700 border-yellow-300',
  'baja':        'bg-green-100 text-green-700 border-green-300',
  'informativa': 'bg-blue-100 text-blue-700 border-blue-300',
}

const PROBABILIDAD_STYLE: Record<string, string> = {
  'alta':  'bg-red-100 text-red-700 border-red-300',
  'media': 'bg-yellow-100 text-yellow-700 border-yellow-300',
  'baja':  'bg-green-100 text-green-700 border-green-300',
}

function CriticidadBadge({ value }: { value: string }) {
  const cls = CRITICIDAD_STYLE[value?.toLowerCase()] ?? 'bg-gray-100 text-gray-600 border-gray-300'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold border ${cls}`}>
      {value}
    </span>
  )
}

function ProbabilidadBadge({ value }: { value: string }) {
  const cls = PROBABILIDAD_STYLE[value?.toLowerCase()] ?? 'bg-gray-100 text-gray-600 border-gray-300'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold border ${cls}`}>
      {value}
    </span>
  )
}

function DetailModal({ threat, onClose }: { threat: Threat; onClose: () => void }) {
  const FIELD_LABELS: [string, string][] = [
    ['ID',                           'ID'],
    ['Fecha Detección',              'Fecha'],
    ['V-A',                          'Tipo'],
    ['Fuente',                       'Fuente'],
    ['CVE(s) Identificados',         'CVE(s)'],
    ['NOMBRE',                       'Producto / Nombre'],
    ['Descripción Técnica',          'Descripción'],
    ['Descripción del Riesgo',       'Riesgo'],
    ['TTPs (MITRE ATT&CK)',          'TTPs'],
    ['Critcidad',                    'Criticidad'],
    ['Probabilidad',                 'Probabilidad'],
    ['Impacto',                      'Impacto'],
    ['Acción Recomendada',           'Acción'],
    ['¿Afecta Activos? (Tenable)',   'Afecta Empresa'],
    ['Comentarios Tenable',          'Detalle Tenable'],
    ['Fecha Escalamiento al Área',   'Fecha de Escalamiento'],
    ['Área Responsable Remediación', 'Área Responsable'],
  ]

  const tipo = String(threat['V-A'] ?? '')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4" onClick={onClose}>
      <div
        className="bg-surface rounded-2xl shadow-2xl border border-brand-300 w-full max-w-2xl max-h-[88vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between px-6 py-4 border-b border-brand-300">
          <div className="flex items-center gap-3">
            <span className="text-2xl">{threatIcon(tipo)}</span>
            <div>
              <p className={`text-xs font-bold uppercase tracking-widest ${severityColor(tipo)}`}>{tipo || 'Amenaza'}</p>
              <h2 className="font-extrabold text-[#1C0A0F] text-lg leading-tight">
                {String(threat['Vulnerabilidad / Amenaza'] ?? '—')}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#A07080] hover:text-brand-500 text-xl font-bold leading-none mt-0.5"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-3">
          {FIELD_LABELS.map(([key, label]) => {
            const val = threat[key]
            if (!val || String(val).trim() === '' || String(val) === 'null') return null
            const strVal = String(val)
            return (
              <div key={key}>
                <p className="text-[10px] font-bold uppercase tracking-widest text-[#B09AA5] mb-0.5">{label}</p>
                {key === 'Critcidad'
                  ? <CriticidadBadge value={strVal} />
                  : key === 'Probabilidad'
                  ? <ProbabilidadBadge value={strVal} />
                  : <p className="text-sm text-[#1C0A0F] whitespace-pre-wrap leading-relaxed">{strVal}</p>
                }
              </div>
            )
          })}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-brand-300 flex justify-end">
          <span className="inline-flex items-center gap-1.5 bg-red-50 text-red-600 text-xs font-bold px-3 py-1.5 rounded-full border border-red-200">
            🔴 ACTIVA
          </span>
        </div>
      </div>
    </div>
  )
}

export default function AlertsBell() {
  const [alerts, setAlerts]         = useState<Threat[]>([])
  const [open, setOpen]             = useState(false)
  const [selected, setSelected]     = useState<Threat | null>(null)
  const [animate, setAnimate]       = useState(false)
  const prevCount                   = useRef(0)
  const ref                         = useRef<HTMLDivElement>(null)

  const fetchAlerts = () => {
    api.alerts.get()
      .then(data => {
        if (data.length > prevCount.current) setAnimate(true)
        prevCount.current = data.length
        setAlerts(data)
      })
      .catch(() => {})
  }

  useEffect(() => {
    fetchAlerts()
    const id = setInterval(fetchAlerts, 30_000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    if (!animate) return
    const t = setTimeout(() => setAnimate(false), 2000)
    return () => clearTimeout(t)
  }, [animate])

  // Close dropdown when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const count = alerts.length

  return (
    <>
      <div ref={ref} className="relative">
        <button
          onClick={() => setOpen(o => !o)}
          className={[
            'relative flex items-center justify-center w-9 h-9 rounded-xl border transition-all',
            count > 0
              ? 'border-red-300 bg-red-50 hover:bg-red-100 text-red-600'
              : 'border-brand-300 bg-surface hover:bg-brand-50 text-[#A07080]',
            animate ? 'animate-bounce' : '',
          ].join(' ')}
          title={count > 0 ? `${count} amenaza(s) activa(s)` : 'Sin amenazas activas'}
        >
          🔔
          {count > 0 && (
            <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[9px] font-extrabold w-4 h-4 rounded-full flex items-center justify-center shadow">
              {count > 9 ? '9+' : count}
            </span>
          )}
        </button>

        {/* Dropdown */}
        {open && (
          <div className="absolute right-0 top-11 w-80 bg-surface border border-brand-300 rounded-2xl shadow-2xl z-40 overflow-hidden">
            <div className="px-4 py-3 border-b border-brand-300 flex items-center justify-between">
              <span className="text-xs font-extrabold text-[#1C0A0F] uppercase tracking-widest">
                Afectan a la Empresa
              </span>
              {count > 0 && (
                <span className="bg-red-500 text-white text-[9px] font-extrabold px-2 py-0.5 rounded-full">
                  {count}
                </span>
              )}
            </div>

            {count === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-[#B09AA5]">
                ✅ Ninguna amenaza afecta activos de la empresa
              </div>
            ) : (
              <ul className="max-h-72 overflow-y-auto divide-y divide-brand-300/50">
                {alerts.map((a, i) => {
                  const tipo  = String(a['V-A'] ?? '')
                  const vuln  = String(a['NOMBRE'] ?? a['CVE(s) Identificados'] ?? '—')
                  const fecha = String(a['Fecha Detección'] ?? '')
                  return (
                    <li key={i}>
                      <button
                        className="w-full text-left px-4 py-3 hover:bg-brand-50 transition-colors flex items-start gap-3"
                        onClick={() => { setSelected(a); setOpen(false) }}
                      >
                        <span className="text-lg mt-0.5 shrink-0">{threatIcon(tipo)}</span>
                        <div className="min-w-0">
                          <p className="text-sm font-bold text-[#1C0A0F] truncate">{vuln}</p>
                          <p className={`text-xs font-semibold ${severityColor(tipo)}`}>{tipo}</p>
                          <p className="text-[10px] text-[#B09AA5] mt-0.5">{fecha}</p>
                        </div>
                        <span className="ml-auto text-[#B09AA5] text-xs shrink-0 mt-1">→</span>
                      </button>
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        )}
      </div>

      {selected && <DetailModal threat={selected} onClose={() => setSelected(null)} />}
    </>
  )
}
