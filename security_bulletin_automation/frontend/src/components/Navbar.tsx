import AlertsBell from './AlertsBell'

type Page = 'dashboard' | 'upload' | 'archive' | 'config' | 'users'

interface Props {
  page:      Page
  setPage:   (p: Page) => void
  user:      string
  role:      string
  onLogout:  () => void
  pending:   number
}

const TABS: { id: Page; icon: string; label: string; adminOnly?: boolean }[] = [
  { id: 'dashboard', icon: '📈', label: 'Dashboard'     },
  { id: 'upload',    icon: '📤', label: 'Procesar'      },
  { id: 'archive',   icon: '📊', label: 'Historial'     },
  { id: 'users',     icon: '👥', label: 'Usuarios',     adminOnly: true },
  { id: 'config',    icon: '⚙️', label: 'Configuración', adminOnly: true },
]

export default function Navbar({ page, setPage, user, role, onLogout, pending }: Props) {
  const now     = new Date().toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' })
  const initial = user?.[0]?.toUpperCase() ?? 'U'
  const visibleTabs = TABS.filter(t => !t.adminOnly || role === 'admin')

  return (
    <header className="bg-surface border-b border-brand-300 shadow-sm">
      {/* Top bar */}
      <div className="flex items-center justify-between px-6 py-2.5 border-b border-brand-300/60">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center text-base shadow-sm">
            🛡️
          </div>
          <span className="font-extrabold text-[#1C0A0F] tracking-widest text-base hidden sm:block">ARGOS</span>
        </div>

        <div className="flex items-center gap-4">
          <span className="text-xs text-[#B09AA5] font-medium hidden sm:block">{now}</span>
          <AlertsBell />
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center text-xs font-bold text-white shadow-sm">
              {initial}
            </div>
            <span className="text-sm font-semibold text-[#3A1520] hidden sm:block">{user}</span>
          </div>
          <button
            onClick={onLogout}
            className="text-xs font-semibold text-[#A07080] border border-brand-300 rounded-lg px-3 py-1.5 hover:text-brand-500 hover:border-brand-500 hover:bg-brand-50 transition-all"
          >
            → Salir
          </button>
        </div>
      </div>

      {/* Nav tabs */}
      <nav className="flex items-stretch px-4">
        {visibleTabs.map(tab => {
          const active = page === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setPage(tab.id)}
              className={[
                'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-all whitespace-nowrap',
                active
                  ? 'text-brand-500 border-brand-500 font-bold'
                  : 'text-[#A07080] border-transparent hover:text-brand-500 hover:border-brand-300',
              ].join(' ')}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
              {tab.id === 'upload' && pending > 0 && (
                <span className="ml-1 bg-orange-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full leading-none">
                  {pending}
                </span>
              )}
            </button>
          )
        })}
      </nav>
    </header>
  )
}
