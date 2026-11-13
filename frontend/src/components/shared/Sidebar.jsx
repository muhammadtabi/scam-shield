import { useAuth } from '../../hooks/useAuth'
import {
  Shield,
  LayoutDashboard,
  ScanSearch,
  Mail,
  Bell,
  FileText,
  Sun,
  Moon,
  LogOut
} from 'lucide-react'

const navItems = [
  { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { id: 'detect',    icon: ScanSearch,      label: 'Scan Now' },
  { id: 'gmail',     icon: Mail,            label: 'Gmail Inbox' },
  { id: 'alerts',    icon: Bell,            label: 'Alerts' },
  { id: 'reports',   icon: FileText,        label: 'Reports' },
]

export default function Sidebar({ page, setPage, theme, onToggleTheme }) {
  const { user, logout } = useAuth()

  return (
    <aside className="side-nav">
      <div className="side-logo">
        <div className="side-logo-icon">
          <Shield size={19} strokeWidth={2.2} />
        </div>
        <div>
          <div className="side-brand">
            Scam Shield
          </div>
          <div className="side-sub">THREAT DETECTION</div>
        </div>
      </div>

      <nav style={{ flex: 1 }}>
        {navItems.map(item => {
          const IconComponent = item.icon
          const isActive = page === item.id
          return (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`nav-button ${isActive ? 'active' : ''}`}
              type="button"
            >
              <IconComponent size={17} strokeWidth={isActive ? 2.2 : 1.8} />
              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      <div className="side-user">
        <button onClick={onToggleTheme} className="theme-btn" type="button">
          {theme === 'dark' ? (
            <>
              <Sun size={15} strokeWidth={2} />
              <span>Light Mode</span>
            </>
          ) : (
            <>
              <Moon size={15} strokeWidth={2} />
              <span>Dark Mode</span>
            </>
          )}
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 10px', marginBottom: 8 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 13, fontWeight: 700, color: 'var(--text-primary)'
          }}>
            {user?.full_name?.[0]?.toUpperCase() || 'U'}
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)',
                          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {user?.full_name || 'User'}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)',
                          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {user?.email}
            </div>
          </div>
        </div>

        <button onClick={logout} className="logout-btn" type="button">
          <LogOut size={14} strokeWidth={2} />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  )
}
