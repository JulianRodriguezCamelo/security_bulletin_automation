import { useCallback, useEffect, useRef, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { api } from '../lib/api'

interface PendingFile { name: string; size: number }

const STAGES = [
  'Inicializando módulos',
  'Extrayendo texto PDF',
  'Análisis IA (Groq)',
  'Consultando VirusTotal',
  'Verificando Tenable',
  'Generando Excel',
  'Completado',
]

const STAGE_KEYWORDS: (string[] | null)[] = [
  null,
  ['Processing:', '---'],
  ['Analyzing with IA', 'Analizando'],
  ['VirusTotal', 'virustotal'],
  ['Tenable', 'tenable'],
  ['Report updated', 'excel_manager', 'add_record'],
  ['Process finished', 'finalizado'],
]

function detectStage(lines: string[]): number {
  let reached = 0
  STAGE_KEYWORDS.forEach((kws, i) => {
    if (!kws) return
    if (lines.some(l => kws.some(k => l.toLowerCase().includes(k.toLowerCase())))) {
      reached = Math.max(reached, i)
    }
  })
  return reached
}

export default function Upload() {
  const [files, setFiles]       = useState<PendingFile[]>([])
  const [running, setRunning]   = useState(false)
  const [logs, setLogs]         = useState<string[]>([])
  const [stage, setStage]       = useState(0)
  const [done, setDone]         = useState<boolean | null>(null)
  const [uploading, setUploading] = useState(false)
  const logRef                  = useRef<HTMLDivElement>(null)
  const sseRef                  = useRef<EventSource | null>(null)

  const loadFiles = () => api.files.list().then(setFiles).catch(() => {})

  useEffect(() => { loadFiles() }, [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  const onDrop = useCallback(async (accepted: File[]) => {
    if (!accepted.length) return
    setUploading(true)
    await api.files.upload(accepted)
    setUploading(false)
    loadFiles()
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'application/pdf': ['.pdf'] },
    multiple: true,
  })

  const removeFile = async (name: string) => {
    await api.files.remove(name)
    loadFiles()
  }

  const handleProcess = () => {
    setRunning(true)
    setLogs([])
    setStage(0)
    setDone(null)

    const sse = new EventSource('/api/process', { withCredentials: true })
    sseRef.current = sse

    sse.addEventListener('message', (e) => {
      const data = JSON.parse(e.data)
      if (data.done !== undefined) {
        setDone(data.code === 0)
        setStage(data.code === 0 ? STAGES.length - 1 : stage)
        setRunning(false)
        sse.close()
        loadFiles()
      } else if (data.line) {
        setLogs(prev => {
          const next = [...prev, data.line]
          setStage(detectStage(next))
          return next
        })
      } else if (data.error) {
        setLogs(prev => [...prev, `ERROR: ${data.error}`])
        setRunning(false)
        setDone(false)
        sse.close()
      }
    })

    sse.onerror = () => {
      if (running) {
        setRunning(false)
        setDone(false)
        sse.close()
      }
    }
  }

  const pct = Math.round((stage / (STAGES.length - 1)) * 100)

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Upload dropzone */}
      <div className="card overflow-hidden">
        <div className="px-6 py-4 border-b border-brand-300 bg-gradient-to-r from-brand-500/5 to-transparent flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center text-lg shadow-sm">📄</div>
          <div>
            <p className="text-sm font-bold text-[#1C0A0F]">Cargar Reporte de Vulnerabilidades</p>
            <p className="text-xs text-[#A07080]">Soporta múltiples PDFs · máx. 200 MB c/u</p>
          </div>
        </div>
        <div className="p-6">
          <div
            {...getRootProps()}
            className={[
              'border-2 border-dashed rounded-xl min-h-[120px] flex flex-col items-center justify-center gap-2 cursor-pointer transition-all',
              isDragActive
                ? 'border-brand-500 bg-brand-50'
                : 'border-brand-300 hover:border-brand-500 hover:bg-brand-50/50',
            ].join(' ')}
          >
            <input {...getInputProps()} />
            <span className="text-2xl">{uploading ? '⏳' : '📁'}</span>
            <p className="text-sm text-[#A07080]">
              {uploading
                ? 'Subiendo archivos…'
                : isDragActive
                ? 'Suelta los PDFs aquí'
                : 'Arrastra PDFs aquí, o haz clic para seleccionar'}
            </p>
          </div>

          {/* Stats row */}
          <div className="mt-4 flex items-center gap-1.5 text-xs text-[#B09AA5]">
            <span>🕐</span>
            <span>{files.length} archivo{files.length !== 1 ? 's' : ''} pendiente{files.length !== 1 ? 's' : ''}</span>
          </div>
        </div>
      </div>

      {/* Pending list */}
      {files.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold text-[#8A5060] uppercase tracking-widest">PDFs Pendientes</span>
            <span className="text-xs font-bold text-brand-500 bg-brand-500/10 border border-brand-500/25 px-2.5 py-0.5 rounded-full">
              {files.length}
            </span>
          </div>
          <div className="space-y-2">
            {files.map(f => (
              <div key={f.name} className="card px-4 py-3 flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-brand-500/8 border border-brand-500/18 flex items-center justify-center text-base shrink-0">📄</div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-[#1C0A0F] truncate" title={f.name}>{f.name}</p>
                  <p className="text-xs text-[#B09AA5]">{Math.round(f.size / 1024)} KB</p>
                </div>
                <span className="text-[10px] font-bold bg-brand-500/8 text-brand-500 border border-brand-500/18 px-2 py-1 rounded shrink-0">PDF</span>
                <button
                  onClick={() => removeFile(f.name)}
                  className="text-[#C4A8B2] hover:text-red-500 transition-colors text-lg leading-none shrink-0"
                  title="Eliminar"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
          <div className="mt-4">
            <button
              onClick={handleProcess}
              disabled={running}
              className="btn-primary px-8"
            >
              {running ? '⏳ Procesando…' : '▶  Procesar Boletines'}
            </button>
          </div>
        </div>
      )}

      {/* Process panel */}
      {(running || done !== null) && (
        <div className="card overflow-hidden">
          <div className="px-6 py-4 border-b border-brand-300 bg-gradient-to-r from-brand-500/5 to-transparent flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center text-sm shadow-sm">⚡</div>
            <span className="text-sm font-bold text-[#1C0A0F]">Ejecutando automatización</span>
          </div>
          <div className="p-6 space-y-4">
            {/* Progress bar */}
            <div>
              <div className="flex justify-between text-xs text-[#B09AA5] mb-1.5">
                <span>{STAGES[stage]}</span>
                <span>{pct}%</span>
              </div>
              <div className="h-2 bg-brand-300 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-brand-500 to-orange-400 rounded-full transition-all duration-500"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>

            {/* Stage list */}
            <div className="divide-y divide-brand-300/60">
              {STAGES.map((lbl, i) => (
                <div key={i} className="flex items-center gap-3 py-2">
                  <span className={[
                    'text-xs w-4 text-center',
                    i < stage  ? 'text-green-500' :
                    i === stage ? 'text-brand-500' : 'text-[#E0CDD3]',
                  ].join(' ')}>
                    {i < stage ? '✓' : i === stage ? '◉' : '○'}
                  </span>
                  <span className={[
                    'text-xs',
                    i < stage  ? 'text-[#3A1520]' :
                    i === stage ? 'text-[#1C0A0F] font-semibold' : 'text-[#C4A8B2]',
                  ].join(' ')}>
                    {lbl}
                  </span>
                </div>
              ))}
            </div>

            {done !== null && (
              <div className={[
                'rounded-xl px-4 py-3 text-sm font-semibold',
                done
                  ? 'bg-green-50 border border-green-200 text-green-700'
                  : 'bg-red-50 border border-red-200 text-red-700',
              ].join(' ')}>
                {done ? '✓ Automatización completada — revisa el Historial' : '✗ Terminó con errores — revisa los logs'}
              </div>
            )}
          </div>

          {/* Log terminal */}
          {logs.length > 0 && (
            <div className="px-6 pb-6">
              <p className="text-[10px] font-bold text-[#B09AA5] uppercase tracking-widest mb-2">LOG</p>
              <div ref={logRef} className="log-terminal">
                {logs.map((l, i) => <div key={i}>{l}</div>)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
