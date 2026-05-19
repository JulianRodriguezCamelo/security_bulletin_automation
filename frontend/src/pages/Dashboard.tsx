import { useEffect, useState } from 'react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
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
  }
  iocs: {
    total: number
    by_type: Record<string, number>
  }
}

const PALETTE = ['#C1294A', '#8B1A33', '#E0506A', '#4A0E24', '#F090A8', '#6B2038', '#D4748A', '#2E0715', '#A83050', '#F5B8C8']

const CAT_COLORS: Record<string, string> = {
  'Vulnerabilidad':          '#C1294A',
  'Amenaza':                 '#8B1A33',
  'Amenaza/Vulnerabilidad':  '#E0506A',
  'Malware':                 '#4A0E24',
  'Phishing':                '#F090A8',
  'APT':                     '#6B2038',
  'Campaña':                 '#D4748A',
  'Poisoning':               '#A83050',
  'Compromiso':              '#F5B8C8',
  'Explotación':             '#2E0715',
  'Otro':                    '#C0A0A8',
}

function colorFor(label: string, idx: number) {
  return CAT_COLORS[label] ?? PALETTE[idx % PALETTE.length]
}

function toEntries(obj: Record<string, number> | undefined | null) {
  if (!obj) return []
  return Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([name, value]) => ({ name, value }))
}

function toMonthData(obj: Record<string, number> | undefined | null) {
  if (!obj) return []
  return Object.entries(obj)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([key, value]) => {
      const [y, m] = key.split('-')
      const label = new Date(+y, +m - 1, 1).toLocaleString('es-CO', { month: 'short', year: '2-digit' })
      return { name: label, value }
    })
}

/* ── Shared sub-components ──────────────────────────────────────────────── */
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

function DonutChart({ data, total, centerLabel }: {
  data: { name: string; value: number }[]
  total: number
  centerLabel: string
}) {
  if (!data.length) return <EmptyChart />
  return (
    <div className="relative w-full" style={{ height: 260 }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={72}
            outerRadius={105}
            paddingAngle={3}
            dataKey="value"
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={colorFor(entry.name, i)} stroke="none" />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 11, color: '#8A5060' }} />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none" style={{ top: '-10px' }}>
        <span className="text-2xl font-extrabold text-[#1C0A0F]">{total}</span>
        <span className="text-[10px] text-[#A07080] font-semibold uppercase tracking-wider">{centerLabel}</span>
      </div>
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
  const categoryData = toEntries(threats.by_category)
  const statusData   = toEntries(threats.by_status)
  const monthData    = toMonthData(threats.by_month)
  const macroData    = toEntries(threats.by_macro)
  const iocData      = toEntries(iocs.by_type).slice(0, 8)

  return (
    <div className="space-y-6">

      {/* ── KPIs ─────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <KpiCard label="Total amenazas"   value={threats.total} sub="boletines procesados" />
        <KpiCard label="Amenazas activas" value={threats.active} sub="requieren atención" accent />
        <KpiCard label="IoCs registrados" value={iocs.total}    sub="indicadores de compromiso" />
      </div>

      {/* ── Row 1: categoría + estado ────────────────────────────────────── */}
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

      {/* ── Row 2: macro-tipos (nueva barra) ────────────────────────────── */}
      <div className="card p-5 space-y-3">
        <SectionTitle>Tipos de amenaza detectados</SectionTitle>
        {macroData.length ? (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={macroData} margin={{ top: 8, right: 24, left: 0, bottom: 0 }} barSize={20}>
              <CartesianGrid strokeDasharray="3 3" stroke="#F0E4E8" vertical={false} />
              <XAxis
                dataKey="name"
                tick={{ fontSize: 11, fill: '#3A1520', fontWeight: 500 }}
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
              <Bar dataKey="value" name="Amenazas" radius={[6, 6, 0, 0]}>
                {macroData.map((_e, i) => (
                  <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : <EmptyChart />}
      </div>

      {/* ── Row 3: evolución mensual ─────────────────────────────────────── */}
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

      {/* ── Row 4: tipos de IoC ─────────────────────────────────────────── */}
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
