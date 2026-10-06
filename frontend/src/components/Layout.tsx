import { NavLink, Outlet } from 'react-router-dom'

const navItems = [
  { to: '/', label: 'Upload', end: true },
  { to: '/queue', label: 'Analysis Queue' },
  { to: '/dashboard', label: 'Dashboard' },
]

export default function Layout() {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-base-600 bg-base-900/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-accent/15 border border-accent/40 flex items-center justify-center">
              <span className="text-accent font-mono font-bold text-sm">ML</span>
            </div>
            <div>
              <div className="font-semibold tracking-tight">MalLens</div>
              <div className="text-[11px] text-slate-500 -mt-0.5">Malware Behavior Analyzer</div>
            </div>
          </div>
          <nav className="flex gap-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive ? 'bg-base-700 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-8">
        <Outlet />
      </main>

      <footer className="border-t border-base-600 py-6">
        <div className="max-w-6xl mx-auto px-6 text-xs text-slate-500 leading-relaxed">
          For authorized security research and incident response only. MalLens analyzes
          user-submitted samples in an isolated environment and never automates offensive
          actions. Misuse for illegal activity is strictly prohibited.
        </div>
      </footer>
    </div>
  )
}
