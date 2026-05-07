import { useAuth } from '../../hooks/useAuth'

const navItems = [
  { id: 'dashboard', icon: '⬡', label: 'Dashboard' },
  { id: 'detect',    icon: '⚡', label: 'Scan Now' },
  { id: 'alerts',    icon: '🚨', label: 'Alerts' },
  { id: 'reports',   icon: '📊', label: 'Reports' },
]

export default function Sidebar({ page, setPage }) {
  const { user, logout } = useAuth()

  return (
    <aside style={{
      width: 240, minHeight: '100vh', background: 'rgba(10, 22, 40, 0.95)',
      borderRight: '1px solid rgba(0,212,255,0.1)',
      display: 'flex', flexDirection: 'column',
      padding: '24px 16px', position: 'fixed', left: 0, top: 0, bottom: 0,
      zIndex: 100
    }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10,
                    padding: '8px 12px', marginBottom: 32 }}>
        <span style={{ fontSize: 24 }}>🛡️</span>
        <div>
          <div style={{ fontFamily: 'Syne', fontWeight: 800, fontSize: 16,
                        background: 'linear-gradient(135deg, #00d4ff, #0ea5e9)',
                        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Scam Shield
          </div>
          <div style={{ fontSize: 10, color: '#475569', fontFamily: 'Space Mono',
                        letterSpacing: '0.1em' }}>AI PROTECTION</div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1 }}>
        {navItems.map(item => (
          <button key={item.id}
            onClick={() => setPage(item.id)}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 12,
              padding: '11px 14px', borderRadius: 10, border: 'none',
              marginBottom: 4, cursor: 'pointer', textAlign: 'left',
              fontFamily: 'DM Sans', fontWeight: 500, fontSize: 14,
              transition: 'all 0.2s',
              background: page === item.id
                ? 'linear-gradient(135deg, rgba(0,212,255,0.15), rgba(14,165,233,0.1))'
                : 'transparent',
              color: page === item.id ? '#00d4ff' : '#94a3b8',
              borderLeft: page === item.id
                ? '2px solid #00d4ff' : '2px solid transparent',
            }}>
            <span style={{ fontSize: 16 }}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      {/* User */}
      <div style={{ borderTop: '1px solid rgba(0,212,255,0.1)', paddingTop: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 12px', marginBottom: 8 }}>
          <div style={{
            width: 34, height: 34, borderRadius: '50%',
            background: 'linear-gradient(135deg, #00d4ff, #0ea5e9)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 14, fontWeight: 700, color: '#020817', fontFamily: 'Syne'
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
        <button onClick={logout}
          style={{
            width: '100%', padding: '9px 14px', borderRadius: 8, cursor: 'pointer',
            background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
            color: '#ef4444', fontSize: 13, fontFamily: 'DM Sans', fontWeight: 500,
            transition: 'all 0.2s'
          }}>
          ← Logout
        </button>
      </div>
    </aside>
  )
}
