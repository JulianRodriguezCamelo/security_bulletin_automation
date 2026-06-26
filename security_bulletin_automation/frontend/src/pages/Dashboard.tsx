import { useEffect, useState } from 'react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
} from 'recharts'

interface DashboardData {
  threats: {
    total: number
    active: number
    by_category: Record<string, number>
    by_macro: Record<string, number>
    by_status: Record<string, number>
    by_month: Record<string, number>
    company_impact: number
    by_source: Record<string, number>
  }
  iocs: {
    total: number
    by_type: Record<string, number>
  }
}

const PALETTE = ['#C1294A', '#8B1A33', '#E0506A', '#4A0E24', '#F090A8', '#6B2038', '#D4748A', '#2E0715', '#A83050', '#F5B8C8']

function colorFor(idx: number) {
  return PALETTE[idx % PALETTE.length]
}

function toEntries(obj: Record<string, number>, limit = 0) {
  const sorted = Object.entries(obj).sort((a, b) => b[1] - a[1])
  if (!limit || sorted.length <= limit) return sorted.map(([name, value]) => ({ name, value }))
  const top = sorted.slice(0, limit)
  const rest = sorted.slice(limit).reduce((acc, [, v]) => acc + v, 0)
  return [...top.map(([name, value]) => ({ name, value })), { name: 'Otros', value: rest }]
}

function toMonthData(obj: Record<string, number>) {
  return Object.entries(obj)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([key, value]) => {
      const [y, m] = key.split('-')
      const label = new Date(+y, +m - 1, 1).toLocaleString('es-CO', { month: 'short', year: '2-digit' })
      return { name: label, value }
    })
}

/* ── Sub-components ─────────────────────────────────────────────────────── */
function KpiCard({ label, value, sub, accent = false }: {
  label: string; value: number | string; sub?: string; accent?: boolean
}) {
  return (
    <div className={`card px-5 py-5 flex flex-col gap-1 ${accent ? 'border-brand-500' : ''}`}>
      <span className="text-[10px] font-bold text-[#A07080] uppercase tracking-widest">{label}</span>
      <span className={`text-3xl font-extrabold leading-none mt-1 ${accent ? 'text-brand-500' : 'text-[#1C0A0F]'}`}>
        {value}
      </span>
      {sub && <span className="text-xs text-[#B09AA5] mt-0.5">{sub}</span>}
    </div>
  )
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-[11px] font-bold text-[#3A1520] uppercase tracking-widest flex items-center gap-2">
      <span className="w-1 h-4 rounded-full bg-brand-500 inline-block shrink-0" />
      {children}
    </h2>
  )
}

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-surface border border-brand-300 rounded-xl shadow-card px-4 py-2.5 text-xs">
      {label && <p className="font-semibold text-[#3A1520] mb-1">{label}</p>}
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ color: p.color ?? p.fill }} className="font-medium">
          {p.name ?? p.dataKey}: <span className="font-bold">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

function EmptyChart() {
  return (
    <div className="flex flex-col items-center justify-center h-36 gap-2 text-[#C0A8B0]">
      <span className="text-3xl">📂</span>
      <span className="text-xs font-medium">Sin datos aún</span>
    </div>
  )
}

/* Custom legend rendered below chart — avoids Recharts positioning conflicts */
function ChartLegend({ data }: { data: { name: string; value: number }[] }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1.5 mt-3 justify-center">
      {data.map((entry, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: colorFor(i) }} />
          <span className="text-[11px] text-[#8A5060] max-w-[160px] truncate" title={entry.name}>
            {entry.name} <span className="font-bold text-[#3A1520]">({entry.value})</span>
          </span>
        </div>
      ))}
    </div>
  )
}

function DonutChart({ data, total, centerLabel }: {
  data: { name: string; value: number }[]
  total: number
  centerLabel: string
}) {
  if (!data.length) return <EmptyChart />
  return (
    <div>
      {/* Fixed height for just the pie — no legend inside Recharts */}
      <div className="relative" style={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={68}
              outerRadius={100}
              paddingAngle={3}
              dataKey="value"
            >
              {data.map((_entry, i) => (
                <Cell key={i} fill={colorFor(i)} stroke="none" />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        {/* Center label — safe because no Recharts Legend inside */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-2xl font-extrabold text-[#1C0A0F]">{total}</span>
          <span className="text-[10px] text-[#A07080] font-semibold uppercase tracking-wider">{centerLabel}</span>
        </div>
      </div>
      {/* Custom legend below */}
      <ChartLegend data={data} />
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════ */
export default function Dashboard() {
  const [data, setData]       = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/dashboard', { credentials: 'include' })
      .then(r => { if (!r.ok) throw new Error(r.statusText); return r.json() })
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-4 border-brand-300 border-t-brand-500 rounded-full animate-spin" />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="card px-6 py-8 text-center text-[#A07080] text-sm">
        Error cargando el dashboard: {error}
      </div>
    )
  }

  const { threats, iocs } = data
  // Limit slices to top 8 + "Otros" to avoid word-cloud effect
  const categoryData = toEntries(threats.by_category, 8)
  const statusData   = toEntries(threats.by_status)
  const monthData    = toMonthData(threats.by_month)
  const macroData    = toEntries(threats.by_macro, 12)
  const iocData      = toEntries(iocs.by_type, 8)

  const _impactPct = threats.total > 0 ? Math.round((threats.company_impact / threats.total) * 100) : 0

  // Mapeo de valores reales del Excel → nombre de display
  const SOURCE_MAP: Record<string, string> = {
    'COLCERT':            'COLCERT',
    'BOLETIN CSIRT CYWEX': 'WEXLER',
    'CSIRT CYWEX':        'WEXLER',
    'Octapus':            'OCTAPUS',
    'octapus.io':         'OCTAPUS',
  }
  const DISPLAY_ORDER = ['COLCERT', 'WEXLER', 'OCTAPUS']
  const SOURCE_COLORS: Record<string, string> = {
    COLCERT: '#C1294A',
    WEXLER:  '#8B1A33',
    OCTAPUS: '#E0506A',
    Otros:   '#A07080',
  }

  // Agrupa los valores del Excel usando el mapeo
  const sourceAccum: Record<string, number> = {}
  for (const [raw, count] of Object.entries(threats.by_source ?? {})) {
    const display = SOURCE_MAP[raw] ?? 'Otros'
    sourceAccum[display] = (sourceAccum[display] ?? 0) + count
  }
  const sourceData = [
    ...DISPLAY_ORDER.map(name => ({ name, value: sourceAccum[name] ?? 0 })),
    ...(sourceAccum['Otros'] ? [{ name: 'Otros', value: sourceAccum['Otros'] }] : []),
  ]

  return (
    <div className="space-y-6">

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard label="Total amenazas"       value={threats.total}          sub="boletines procesados" />
        <KpiCard label="Afectan a la empresa" value={threats.active}         sub="confirmado por Tenable" accent />
        <KpiCard label="IoCs registrados"     value={iocs.total}             sub="indicadores de compromiso" />
        <KpiCard label="Sin gestionar"        value={threats.company_impact} sub="Estado Activo — SOC pendiente" />
      </div>

      {/* Row 1: categoría + estado */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="card p-5 space-y-3">
          <SectionTitle>Categoría de amenaza</SectionTitle>
          <DonutChart data={categoryData} total={threats.total} centerLabel="total" />
        </div>
        <div className="card p-5 space-y-3">
          <SectionTitle>Estado de amenazas</SectionTitle>
          <DonutChart data={statusData} total={threats.total} centerLabel="total" />
        </div>
      </div>

      {/* Row 2: tipos de amenaza (bar) */}
      <div className="card p-5 space-y-3">
        <SectionTitle>Tipos de amenaza detectados</SectionTitle>
        {macroData.length ? (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={macroData} margin={{ top: 8, right: 24, left: 0, bottom: 60 }} barSize={20}>
              <CartesianGrid strokeDasharray="3 3" stroke="#F0E4E8" vertical={false} />
              <XAxis
                dataKey="name"
                tick={{ fontSize: 10, fill: '#3A1520', fontWeight: 500 }}
                axisLine={false}
                tickLine={false}
                angle={-35}
                textAnchor="end"
                interval={0}
              />
              <YAxis
                tick={{ fontSize: 10, fill: '#A07080' }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" name="Amenazas" radius={[6, 6, 0, 0]}>
                {macroData.map((_e, i) => (
                  <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : <EmptyChart />}
      </div>

      {/* Row 3: evolución mensual */}
      <div className="card p-5 space-y-3">
        <SectionTitle>Evolución mensual de boletines</SectionTitle>
        {monthData.length ? (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={monthData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#C1294A" stopOpacity={0.22} />
                  <stop offset="95%" stopColor="#C1294A" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#F0E4E8" />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#A07080' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: '#A07080' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="value"
                name="Boletines"
                stroke="#C1294A"
                strokeWidth={2.5}
                fill="url(#areaGrad)"
                dot={{ fill: '#C1294A', r: 4, strokeWidth: 0 }}
                activeDot={{ r: 6, fill: '#8B1A33' }}
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : <EmptyChart />}
      </div>

      {/* Row 4: boletines por fuente */}
      <div className="card p-5 space-y-3">
        <SectionTitle>Boletines procesados por fuente</SectionTitle>
        {sourceData.some(d => d.value > 0) ? (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={sourceData} margin={{ top: 8, right: 24, left: 0, bottom: 8 }} barSize={48}>
              <CartesianGrid strokeDasharray="3 3" stroke="#F0E4E8" vertical={false} />
              <XAxis
                dataKey="name"
                tick={{ fontSize: 12, fill: '#3A1520', fontWeight: 600 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: '#A07080' }}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" name="Boletines" radius={[8, 8, 0, 0]}>
                {sourceData.map((entry) => (
                  <Cell key={entry.name} fill={SOURCE_COLORS[entry.name] ?? '#C1294A'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : <EmptyChart />}
        {/* Totals row */}
        <div className="flex gap-4 justify-center flex-wrap pt-1">
          {sourceData.filter(d => d.value > 0).map(d => (
            <div key={d.name} className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: SOURCE_COLORS[d.name] ?? '#C1294A' }} />
              <span className="text-[11px] text-[#8A5060] font-medium">{d.name}</span>
              <span className="text-[11px] font-bold text-[#3A1520]">{d.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Row 5: tipos de IoC */}
      <div className="card p-5 space-y-3">
        <SectionTitle>Tipos de IoC</SectionTitle>
        {iocData.length ? (
          <ResponsiveContainer width="100%" height={Math.max(160, iocData.length * 38)}>
            <BarChart
              data={iocData}
              layout="vertical"
              margin={{ top: 0, right: 24, left: 10, bottom: 0 }}
              barSize={16}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#F0E4E8" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#A07080' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fontSize: 11, fill: '#3A1520', fontWeight: 500 }}
                axisLine={false}
                tickLine={false}
                width={110}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" name="IoCs" radius={[0, 6, 6, 0]}>
                {iocData.map((_e, i) => (
                  <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : <EmptyChart />}
      </div>

    </div>
  )
}
