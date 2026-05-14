import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  useReactTable,
} from '@tanstack/react-table'
import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../lib/api'

type Row = Record<string, unknown>

const SEV_COLORS: Record<string, string> = {
  vulnerabilidad: 'text-violet-600 bg-violet-50 border-violet-300',
  amenaza:        'text-brand-500 bg-brand-50 border-brand-300',
  malware:        'text-red-600 bg-red-50 border-red-300',
  apt:            'text-violet-600 bg-violet-50 border-violet-300',
  phishing:       'text-pink-600 bg-pink-50 border-pink-300',
  ransomware:     'text-red-600 bg-red-50 border-red-300',
}

function typeBadge(val: string) {
  const key = val?.toLowerCase() ?? ''
  const cls = Object.entries(SEV_COLORS).find(([k]) => key.includes(k))?.[1]
    ?? 'text-[#8A5060] bg-brand-50 border-brand-300'
  return <span className={`badge border text-[11px] ${cls}`}>{val}</span>
}

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

function DataTable({
  data,
  setData,
  height = 420,
}: {
  data: Row[]
  setData: (d: Row[]) => void
  height?: number
}) {
  const [globalFilter, setGlobalFilter] = useState('')

  const columns = useMemo<ColumnDef<Row>[]>(() => {
    if (!data.length) return []
    return Object.keys(data[0]).map(key => ({
      accessorKey: key,
      header: key,
      size: 140,
      cell: ({ row, getValue }) => {
        const val = getValue()
        const isType = key.toLowerCase().includes('tipo')
        if (isType && typeof val === 'string' && val) return typeBadge(val)
        return (
          <EditableCell
            value={val}
            onChange={v => {
              const next = data.map((r, i) =>
                i === row.index ? { ...r, [key]: v } : r
              )
              setData(next)
            }}
          />
        )
      },
    }))
  }, [data, setData])

  const table = useReactTable({
    data,
    columns,
    state: { globalFilter },
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-[#B09AA5]">{table.getRowModel().rows.length} de {data.length} registros — <em>haz clic en una celda para editarla</em></span>
        <input
          className="input w-56 text-xs py-1.5"
          placeholder="Buscar…"
          value={globalFilter}
          onChange={e => setGlobalFilter(e.target.value)}
        />
      </div>
      <div className="border border-brand-300 rounded-xl overflow-auto shadow-sm" style={{ maxHeight: height }}>
        <table className="w-full border-collapse text-xs">
          <thead className="sticky top-0 bg-[#fdf2f5] z-10">
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id}>
                {hg.headers.map(h => (
                  <th
                    key={h.id}
                    style={{ width: h.getSize() }}
                    className="px-3 py-2 text-left text-[10px] font-bold text-[#8A5060] uppercase tracking-wide border-b border-brand-300 whitespace-nowrap"
                  >
                    {flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row, ri) => (
              <tr key={row.id} className={ri % 2 === 0 ? 'bg-white' : 'bg-brand-50/40'}>
                {row.getVisibleCells().map(cell => (
                  <td key={cell.id} className="px-3 py-2 border-b border-brand-300/40 max-w-[200px]">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function Archive() {
  const [threats, setThreats]   = useState<Row[]>([])
  const [iocs, setIocs]         = useState<Row[]>([])
  const [tab, setTab]           = useState<'threats' | 'iocs'>('threats')
  const [loading, setLoading]   = useState(true)
  const [saving, setSaving]     = useState(false)
  const [msg, setMsg]           = useState<{ ok: boolean; text: string } | null>(null)
  const [noExcel, setNoExcel]   = useState(false)
  const [loadErr, setLoadErr]   = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    setLoadErr(null)
    try {
      const [t, i] = await Promise.all([api.archive.getThreats(), api.archive.getIocs()])
      setNoExcel(!t.length && !i.length)
      setThreats(t)
      setIocs(i)
    } catch (err: unknown) {
      setLoadErr(err instanceof Error ? err.message : String(err))
      setNoExcel(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const save = async () => {
    setSaving(true)
    setMsg(null)
    try {
      await Promise.all([
        api.archive.updateThreats(threats),
        api.archive.updateIocs(iocs),
      ])
      setMsg({ ok: true, text: '✓ Cambios guardados en el archivo Excel' })
    } catch (err: unknown) {
      setMsg({ ok: false, text: `✗ ${err instanceof Error ? err.message : 'Error al guardar'}` })
    } finally {
      setSaving(false)
    }
  }

  // KPI helpers
  const typeCol   = threats[0] ? Object.keys(threats[0]).find(k => k.toLowerCase().includes('tipo'))   : undefined
  const statusCol = threats[0] ? Object.keys(threats[0]).find(k => k.toLowerCase().includes('estado')) : undefined
  const dateCol   = threats[0] ? Object.keys(threats[0]).find(k => k.toLowerCase().includes('fecha'))  : undefined

  const activeCount = statusCol
    ? threats.filter(r => String(r[statusCol] ?? '').toLowerCase().includes('activ')).length
    : 0
  const typeCount = typeCol
    ? new Set(threats.map(r => r[typeCol])).size
    : 0
  const lastDate = dateCol
    ? [...threats].sort((a, b) => String(b[dateCol]).localeCompare(String(a[dateCol])))[0]?.[dateCol]
    : '—'

  const kpis = [
    { icon: '📋', label: 'Total Amenazas',  value: threats.length, color: '#C1294A'  },
    { icon: '⚡', label: 'Activas',          value: activeCount,    color: '#DC2626'  },
    { icon: '🏷️', label: 'Tipos distintos',  value: typeCount,      color: '#7c3aed'  },
    { icon: '📅', label: 'Último registro', value: String(lastDate ?? '—'), color: '#16a34a' },
  ]

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-[#A07080] text-sm">Cargando datos…</div>
  )

  if (noExcel) return (
    <div className="max-w-2xl mx-auto mt-12">
      <div className="card p-14 text-center border-2 border-dashed border-brand-300">
        <div className="text-5xl mb-4 opacity-25">📁</div>
        <p className="text-sm font-bold text-[#7A4A55]">Sin datos todavía</p>
        {loadErr ? (
          <p className="text-xs text-red-500 mt-2 font-mono break-all">{loadErr}</p>
        ) : (
          <p className="text-xs text-[#C4A8B2] mt-2">
            Procesa al menos un PDF desde <strong className="text-brand-500">Procesar</strong>
          </p>
        )}
        <button onClick={load} className="btn-secondary mt-4 text-xs">↺ Reintentar</button>
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
        <p className="text-sm text-[#A07080] mt-1">Registro histórico de amenazas e indicadores de compromiso (IoCs).</p>
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
          <DataTable data={threats} setData={setThreats} height={480} />
        ) : (
          <DataTable data={iocs} setData={setIocs} height={420} />
        )}
      </div>

      {/* Footer actions */}
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={save} disabled={saving} className="btn-primary">
          {saving ? '💾 Guardando…' : '💾  Guardar cambios'}
        </button>
        <a
          href={api.archive.downloadUrl()}
          download="Informe_Amenazas.xlsx"
          className="btn-secondary"
        >
          ⬇  Descargar Excel
        </a>
        <button onClick={load} className="btn-secondary">
          ↺  Recargar
        </button>
        {msg && (
          <span className={`text-xs font-semibold ${msg.ok ? 'text-green-700' : 'text-red-600'}`}>
            {msg.text}
          </span>
        )}
      </div>
    </div>
  )
}
