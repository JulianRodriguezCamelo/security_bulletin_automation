import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../lib/api'

type Row = Record<string, unknown>

// ── Normalización de nombres de columna (Excel viejo → nuevo) ─────────────────

const THREAT_ALIASES: Record<string, string> = {
  'Tipo de Amenaza':                           'V-A',
  'Fuente de Detección':                       'Fuente',
  'Vulnerabilidad / Amenaza':                  'NOMBRE',
  'Descripción':                               'Descripción Técnica',
  'CRITICIDAD':                                'Critcidad',
  'PROBABILIDAD':                              'Probabilidad',
  'Posible Impacto':                           'Impacto',
  'Indicadores (IoC)':                         'Indicadores (IoC)', // ignorado en UI
  'TTP (Técnicas, Tácticas y Procedimientos)': 'TTPs (MITRE ATT&CK)',
  'Comentarios SOC':                           'Comentarios Tenable',
  'FECHA DE ESCALAMIENTO':                     'Fecha Escalamiento al Área',
  'AREA RESPONSABLE DE REMEDIACION ':          'Área Responsable Remediación',
  'AREA RESPONSABLE DE REMEDIACION':           'Área Responsable Remediación',
  'Comentarios FIDU':                          'Comentarios Tenable',
  'BLOQUEO ANTIVIRUS':                         'Bloqueo Antivirus',
  'BLOQUEO FIREWALL':                          'Bloqueo Firewall',
  'CASO FIREWALL':                             'Caso Firewall',
}

const IOC_ALIASES: Record<string, string> = {
  'TIPO DE IOC': 'Tipo de IoC',
  'IOC':         'Indicador (IoC)',
  'ANTIVIRUS':   'Bloqueo Antivirus',
  'FIREWALL':    'Bloqueo Firewall',
}

function normalizeRows(rows: Row[], aliases: Record<string, string>): Row[] {
  return rows.map(row => {
    const out: Row = {}
    for (const [k, v] of Object.entries(row)) {
      const nk = aliases[k] ?? k
      const hasValue = v !== null && v !== undefined && v !== ''
      const existingHasValue = out[nk] !== null && out[nk] !== undefined && out[nk] !== ''
      if (!(nk in out) || (hasValue && !existingHasValue)) {
        out[nk] = v
      }
    }
    return out
  })
}

// ── Definición de grupos de columnas (igual que el Excel) ─────────────────────

interface ColDef { key: string; size?: number }
interface ColGroup { label: string; color: string; cols: ColDef[] }

const THREAT_GROUPS: ColGroup[] = [
  {
    label: 'IDENTIFICACIÓN',
    color: '#1F3864',
    cols: [
      { key: 'ID',                    size: 80  },
      { key: 'Fecha Detección',       size: 120 },
      { key: 'Fuente',                size: 140 },
      { key: 'V-A',                   size: 130 },
      { key: 'CVE(s) Identificados',  size: 160 },
      { key: 'NOMBRE',                size: 160 },
    ],
  },
  {
    label: 'DESCRIPCIÓN',
    color: '#7B3811',
    cols: [
      { key: 'Descripción Técnica',   size: 280 },
      { key: 'Descripción del Riesgo',size: 220 },
      { key: 'TTPs (MITRE ATT&CK)',   size: 180 },
    ],
  },
  {
    label: 'ANÁLISIS DE RIESGO',
    color: '#843C0C',
    cols: [
      { key: 'Probabilidad',          size: 110 },
      { key: 'Impacto',               size: 160 },
      { key: 'Critcidad',             size: 110 },
    ],
  },
  {
    label: 'GESTIÓN Y ESCALAMIENTO',
    color: '#1E5631',
    cols: [
      { key: 'Acción Recomendada',             size: 200 },
      { key: 'Área Responsable Remediación',   size: 180 },
      { key: 'Fecha Escalamiento al Área',     size: 150 },
    ],
  },
  {
    label: 'VALIDACIÓN TENABLE',
    color: '#4B0082',
    cols: [
      { key: '¿Afecta Activos? (Tenable)', size: 160 },
      { key: 'Comentarios Tenable',        size: 260 },
    ],
  },
  {
    label: 'CONTROLES TÉCNICOS',
    color: '#375623',
    cols: [
      { key: 'Bloqueo Antivirus', size: 130 },
      { key: 'Bloqueo Firewall',  size: 130 },
      { key: 'Caso Firewall',     size: 130 },
    ],
  },
]

const IOC_GROUPS: ColGroup[] = [
  {
    label: 'DETALLE DE INDICADORES DE COMPROMISO (IoC) — ISO 27001 A.5.7',
    color: '#1F3864',
    cols: [
      { key: 'ID Amenaza',       size: 110 },
      { key: 'Tipo de IoC',      size: 140 },
      { key: 'Indicador (IoC)',  size: 340 },
    ],
  },
  {
    label: 'ACCIONES DE BLOQUEO',
    color: '#375623',
    cols: [
      { key: 'Bloqueo Antivirus', size: 150 },
      { key: 'Bloqueo Firewall',  size: 150 },
    ],
  },
]

// ── Badges ────────────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  vulnerabilidad: 'text-violet-600 bg-violet-50 border-violet-300',
  amenaza:        'text-brand-500 bg-brand-50 border-brand-300',
  malware:        'text-red-600 bg-red-50 border-red-300',
  apt:            'text-violet-600 bg-violet-50 border-violet-300',
  phishing:       'text-pink-600 bg-pink-50 border-pink-300',
  ransomware:     'text-red-600 bg-red-50 border-red-300',
}

const CRITICIDAD_STYLE: Record<string, string> = {
  'crítica':     'text-red-700 bg-red-100 border-red-300',
  'alta':        'text-orange-700 bg-orange-100 border-orange-300',
  'media':       'text-yellow-700 bg-yellow-100 border-yellow-300',
  'baja':        'text-green-700 bg-green-100 border-green-300',
  'informativa': 'text-blue-700 bg-blue-100 border-blue-300',
}

const PROBABILIDAD_STYLE: Record<string, string> = {
  'alta':  'text-red-700 bg-red-100 border-red-300',
  'media': 'text-yellow-700 bg-yellow-100 border-yellow-300',
  'baja':  'text-green-700 bg-green-100 border-green-300',
}

const TENABLE_STYLE: Record<string, string> = {
  'sí':       'text-green-700 bg-green-100 border-green-300',
  'no aplica':'text-blue-600 bg-blue-50 border-blue-200',
  'no':       'text-gray-600 bg-gray-100 border-gray-300',
}

const BLOQUEO_STYLE: Record<string, string> = {
  'aplicado':  'text-green-700 bg-green-100 border-green-300',
  'no aplica': 'text-gray-500 bg-gray-50 border-gray-200',
  'aplica':    'text-green-700 bg-green-100 border-green-300',
}

function b(cls: string, val: string, extra = '') {
  return <span className={`badge border text-[11px] ${extra} ${cls}`}>{val}</span>
}

function cellBadge(key: string, val: string) {
  if (key === 'V-A') {
    const cls = Object.entries(SEV_COLORS).find(([k]) => val.toLowerCase().includes(k))?.[1] ?? 'text-[#8A5060] bg-brand-50 border-brand-300'
    return b(cls, val)
  }
  if (key === 'Critcidad') return b(CRITICIDAD_STYLE[val.toLowerCase()] ?? 'text-gray-600 bg-gray-100 border-gray-300', val, 'font-bold')
  if (key === 'Probabilidad') return b(PROBABILIDAD_STYLE[val.toLowerCase()] ?? 'text-gray-600 bg-gray-100 border-gray-300', val, 'font-bold')
  if (key === '¿Afecta Activos? (Tenable)') {
    const k = val.toLowerCase().startsWith('sí') ? 'sí' : val.toLowerCase()
    return b(TENABLE_STYLE[k] ?? 'text-gray-600 bg-gray-100 border-gray-300', val, 'font-bold')
  }
  if (key === 'Bloqueo Antivirus' || key === 'Bloqueo Firewall') {
    return b(BLOQUEO_STYLE[val.toLowerCase()] ?? 'text-gray-600 bg-gray-100 border-gray-300', val)
  }
  return null
}

// ── Celda editable ────────────────────────────────────────────────────────────

function EditableCell({ value, onChange }: { value: unknown; onChange: (v: string) => void }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft]     = useState(String(value ?? ''))
  const ref = useRef<HTMLInputElement>(null)

  useEffect(() => { if (editing) ref.current?.focus() }, [editing])

  const commit = () => { onChange(draft); setEditing(false) }

  if (editing) {
    return (
      <input
        ref={ref}
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') setEditing(false) }}
        className="w-full border border-brand-400 rounded px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand-500"
      />
    )
  }
  return (
    <span
      className="cursor-pointer hover:bg-brand-50 rounded px-1 py-0.5 block truncate text-xs"
      title={String(value ?? '')}
      onClick={() => setEditing(true)}
    >
      {String(value ?? '')}
    </span>
  )
}

// ── DataTable ─────────────────────────────────────────────────────────────────

function DataTable({
  data,
  setData,
  groups,
  height = 420,
}: {
  data: Row[]
  setData: (d: Row[]) => void
  groups: ColGroup[]
  height?: number
}) {
  const [globalFilter, setGlobalFilter] = useState('')

  const columns = useMemo<ColumnDef<Row>[]>(() => {
    return groups.map(group => ({
      id:     group.label,
      header: group.label,
      meta:   { color: group.color },
      columns: group.cols.map(col => ({
        accessorKey: col.key,
        header:      col.key,
        size:        col.size ?? 140,
        cell: ({ row, getValue }) => {
          const val = getValue()
          const strVal = typeof val === 'string' ? val : String(val ?? '')
          if (strVal) {
            const badge = cellBadge(col.key, strVal)
            if (badge) return badge
          }
          return (
            <EditableCell
              value={val}
              onChange={v => {
                const next = data.map((r, i) =>
                  i === row.index ? { ...r, [col.key]: v } : r
                )
                setData(next)
              }}
            />
          )
        },
      })),
    }))
  }, [data, setData, groups])

  const table = useReactTable({
    data,
    columns,
    state: { globalFilter },
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  })

  const headerGroups = table.getHeaderGroups()

  return (
    <div>
      {/* Barra superior */}
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-[#B09AA5]">
          {table.getRowModel().rows.length} de {data.length} registros —{' '}
          <em>haz clic en una celda para editarla</em>
        </span>
        <input
          className="input w-56 text-xs py-1.5"
          placeholder="Buscar…"
          value={globalFilter}
          onChange={e => setGlobalFilter(e.target.value)}
        />
      </div>

      {/* Tabla */}
      <div
        className="border border-brand-300 rounded-xl overflow-auto shadow-sm"
        style={{ maxHeight: height }}
      >
        <table className="w-full border-collapse text-xs" style={{ minWidth: 'max-content' }}>
          <thead className="sticky top-0 z-10">
            {headerGroups.map((hg, hgIdx) => (
              <tr key={hg.id}>
                {hg.headers.map(h => {
                  const meta = h.column.columnDef.meta as { color?: string } | undefined

                  if (hgIdx === 0) {
                    // Fila de grupos con color
                    return (
                      <th
                        key={h.id}
                        colSpan={h.colSpan}
                        style={{ background: meta?.color ?? '#1F3864' }}
                        className="px-3 py-1.5 text-center text-[10px] font-extrabold text-white uppercase tracking-widest border-b border-white/20 whitespace-nowrap"
                      >
                        {flexRender(h.column.columnDef.header, h.getContext())}
                      </th>
                    )
                  }

                  // Fila de nombres de columna
                  return (
                    <th
                      key={h.id}
                      style={{ width: h.getSize() }}
                      className="px-3 py-2 text-left text-[10px] font-bold text-[#8A5060] uppercase tracking-wide border-b border-brand-300 whitespace-nowrap bg-[#fdf2f5]"
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td
                  colSpan={groups.reduce((acc, g) => acc + g.cols.length, 0)}
                  className="px-4 py-8 text-center text-xs text-[#C4A8B2]"
                >
                  Sin resultados
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row, ri) => (
                <tr key={row.id} className={ri % 2 === 0 ? 'bg-white' : 'bg-brand-50/40'}>
                  {row.getVisibleCells().map(cell => (
                    <td
                      key={cell.id}
                      className="px-3 py-2 border-b border-brand-300/40"
                      style={{ maxWidth: cell.column.getSize() }}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Página Archive ────────────────────────────────────────────────────────────

export default function Archive() {
  const [threats, setThreats] = useState<Row[]>([])
  const [iocs, setIocs]       = useState<Row[]>([])
  const [tab, setTab]         = useState<'threats' | 'iocs'>('threats')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [msg, setMsg]         = useState<{ ok: boolean; text: string } | null>(null)
  const [noExcel, setNoExcel] = useState(false)
  const [error, setError]     = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    setNoExcel(false)
    try {
      const [t, i] = await Promise.all([api.archive.getThreats(), api.archive.getIocs()])
      setThreats(normalizeRows(t, THREAT_ALIASES))
      setIocs(normalizeRows(i, IOC_ALIASES))
      if (!t.length && !i.length) setNoExcel(true)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Error desconocido al cargar el historial')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const save = async () => {
    setSaving(true)
    setMsg(null)
    try {
      await api.archive.save(threats, iocs)
      setMsg({ ok: true, text: '✓ Cambios guardados en el archivo Excel' })
    } catch (err: unknown) {
      setMsg({ ok: false, text: `✗ ${err instanceof Error ? err.message : 'Error al guardar'}` })
    } finally {
      setSaving(false)
    }
  }

  const [migrating, setMigrating] = useState(false)

  const migrate = async () => {
    setMigrating(true)
    setMsg(null)
    try {
      await api.archive.migrate()
      setMsg({ ok: true, text: '✓ Formato actualizado — recargando datos…' })
      await load()
    } catch (err: unknown) {
      setMsg({ ok: false, text: `✗ ${err instanceof Error ? err.message : 'Error al migrar'}` })
    } finally {
      setMigrating(false)
    }
  }

  // KPIs
  const activeCount = threats.filter(r =>
    String(r['¿Afecta Activos? (Tenable)'] ?? '').toLowerCase().startsWith('sí') ||
    String(r['Comentarios Tenable'] ?? '').includes('AFECTA LA EMPRESA')
  ).length
  const typeCount = new Set(threats.map(r => r['V-A'])).size
  const lastDate  = [...threats]
    .sort((a, b) => String(b['Fecha Detección']).localeCompare(String(a['Fecha Detección'])))[0]
    ?.['Fecha Detección']

  const kpis = [
    { icon: '📋', label: 'Total Amenazas',  value: threats.length,       color: '#C1294A' },
    { icon: '⚡', label: 'Afectan Empresa',  value: activeCount,          color: '#DC2626' },
    { icon: '🏷️', label: 'Tipos distintos',  value: typeCount,            color: '#7c3aed' },
    { icon: '📅', label: 'Último registro', value: String(lastDate ?? '—'), color: '#16a34a' },
  ]

  // ── Renders ──────────────────────────────────────────────────────────────────

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-[#A07080] text-sm">Cargando datos…</div>
  )

  if (error) return (
    <div className="max-w-2xl mx-auto mt-12">
      <div className="card p-10 text-center border-2 border-red-300 bg-red-50">
        <div className="text-4xl mb-3">⚠️</div>
        <p className="text-sm font-bold text-red-700">Error al cargar el historial</p>
        <p className="text-xs text-red-500 mt-2 font-mono break-all">{error}</p>
        <button onClick={load} className="btn-primary mt-5">↺ Reintentar</button>
      </div>
    </div>
  )

  if (noExcel) return (
    <div className="max-w-2xl mx-auto mt-12">
      <div className="card p-14 text-center border-2 border-dashed border-brand-300">
        <div className="text-5xl mb-4 opacity-25">📁</div>
        <p className="text-sm font-bold text-[#7A4A55]">Sin datos todavía</p>
        <p className="text-xs text-[#C4A8B2] mt-2">
          Procesa al menos un PDF desde <strong className="text-brand-500">Procesar</strong>
        </p>
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-[#1C0A0F] flex items-center gap-2">
          <span>📊</span> Archivo de Boletines
        </h1>
        <p className="text-sm text-[#A07080] mt-1">
          Registro histórico de amenazas e indicadores de compromiso (IoCs).
        </p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {kpis.map(k => (
          <div key={k.label} className="card p-4" style={{ borderTop: `3px solid ${k.color}` }}>
            <div className="text-xl mb-2">{k.icon}</div>
            <div className="text-[10px] font-bold text-[#8A5060] uppercase tracking-wide">{k.label}</div>
            <div className="text-2xl font-extrabold text-[#1C0A0F] mt-1">{k.value}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="border-b border-brand-300 flex gap-0">
        {(['threats', 'iocs'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={[
              'px-5 py-3 text-sm font-medium border-b-2 transition-all',
              tab === t
                ? 'text-brand-500 border-brand-500 font-bold'
                : 'text-[#A07080] border-transparent hover:text-brand-500',
            ].join(' ')}
          >
            {t === 'threats' ? '🗂️  Registro de Amenazas' : '🔍  Detalle de IoCs'}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="card p-5">
        {tab === 'threats' ? (
          <DataTable data={threats} setData={setThreats} groups={THREAT_GROUPS} height={500} />
        ) : (
          <DataTable data={iocs} setData={setIocs} groups={IOC_GROUPS} height={440} />
        )}
      </div>

      {/* Footer */}
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={save} disabled={saving} className="btn-primary">
          {saving ? '💾 Guardando…' : '💾  Guardar cambios'}
        </button>
        <button onClick={migrate} disabled={migrating} className="btn-secondary" title="Migra columnas antiguas al formato actual">
          {migrating ? '⚙️ Migrando…' : '⚙️  Actualizar formato'}
        </button>
        <a href={api.archive.downloadUrl()} download="Informe_Amenazas.xlsx" className="btn-secondary">
          ⬇  Descargar Excel
        </a>
        <button onClick={load} className="btn-secondary">↺  Recargar</button>
        {msg && (
          <span className={`text-xs font-semibold ${msg.ok ? 'text-green-700' : 'text-red-600'}`}>
            {msg.text}
          </span>
        )}
      </div>
    </div>
  )
}
