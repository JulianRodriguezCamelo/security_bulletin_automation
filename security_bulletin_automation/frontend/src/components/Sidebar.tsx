export default function Sidebar() {
  return (
    <aside className="hidden md:flex flex-col w-52 shrink-0 bg-gradient-to-b from-brand-900 to-brand-950 shadow-[4px_0_24px_rgba(74,14,36,0.18)]">
      {/* Brand */}
      <div className="flex flex-col items-center gap-3 px-4 py-7 border-b border-white/10">
        <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-orange-400/25 to-brand-500/25 border border-orange-400/40 flex items-center justify-center text-3xl">
          🛡️
        </div>
        <div className="text-center">
          <p className="text-white font-extrabold tracking-widest text-lg leading-none">ARGOS</p>
          <p className="text-white/30 text-[10px] mt-1 leading-snug">
            Sistema de Inteligencia<br />de Vulnerabilidades
          </p>
        </div>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Status footer */}
      <div className="px-4 py-4 border-t border-white/8 bg-black/30 backdrop-blur-sm">
        <div className="flex items-center gap-2.5">
          <span className="text-sm">⚡</span>
          <div className="flex-1 min-w-0">
            <p className="text-[11px] font-bold text-white/80 tracking-wide">GROQ IA</p>
            <p className="text-[10px] text-white/30 truncate">llama-3.3-70b-versatile</p>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 shadow-[0_0_6px_rgba(74,222,128,0.7)]" />
            <span className="text-[10px] text-green-400 font-semibold">Online</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
