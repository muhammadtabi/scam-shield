import { useAuth } from '../../hooks/useAuth'

const navItems = [
  { id: 'dashboard', icon: '⬡', label: 'Dashboard' },
  { id: 'detect',    icon: '⚡', label: 'Scan Now' },
  { id: 'alerts',    icon: '🚨', label: 'Alerts' },
  { id: 'reports',   icon: '📊', label: 'Reports' },
]

export default function Sidebar({ page, setPage, theme, onToggleTheme }) {
  const { user, logout } = useAuth()

  return (
    <aside className="side-nav">
      <div className="side-logo">
        <span style={{ fontSize: 24 }}>🛡️</span>
        <div>
          <div className="side-brand">
            Scam Shield
          </div>
          <div className="side-sub">AI PROTECTION</div>
        </div>
      </div>

      <nav style={{ flex: 1 }}>
        {navItems.map(item => (
          <button key={item.id}
            onClick={() => setPage(item.id)}
            className={`nav-button ${page === item.id ? 'active' : ''}`}>
            <span style={{ fontSize: 16 }}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div className="side-user">
        <button onClick={onToggleTheme} className="theme-btn" type="button">
          {theme === 'dark' ? '☀ Light Theme' : '🌙 Dark Theme'}
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 12px', marginBottom: 8 }}>
          <div style={{
            width: 34, height: 34, borderRadius: '50%',
            background: 'linear-gradient(135deg, #00d4ff, #0ea5e9)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 14, fontWeight: 700, color: '#020817', fontFamily: 'Sora'
          }}>
            {user?.full_name?.[0]?.toUpperCase() || 'U'}
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>
              {user?.full_name || 'User'}
            </div>
            <div style={{ fontSize: 11, color: '#475569' }}>{user?.email}</div>
          </div>
        </div>
        <button onClick={logout} className="logout-btn">
          ← Logout
        </button>
      </div>
    </aside>
  )
}
