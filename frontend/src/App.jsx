import { useEffect, useState } from 'react'
import { AuthProvider, useAuth } from './hooks/useAuth'
import Login    from './components/auth/Login'
import Register from './components/auth/Register'
import Sidebar  from './components/shared/Sidebar'
import Dashboard from './components/dashboard/Dashboard'
import Detection from './components/detection/Detection'
import Alerts   from './components/alerts/Alerts'
import Reports  from './components/reports/Reports'

function AuthPage() {
  const [isLogin, setIsLogin] = useState(true)
  return (
    <div className="grid-bg auth-shell">
      <div className="ambient-orb" />
      {isLogin
        ? <Login    onSwitch={() => setIsLogin(false)} />
        : <Register onSwitch={() => setIsLogin(true)} />
      }
    </div>
  )
}

function AppContent() {
  const { user, loading } = useAuth()
  const [page, setPage] = useState('dashboard')
  const [theme, setTheme] = useState(() => {
    if (typeof window === 'undefined') return 'dark'
    const stored = localStorage.getItem('scam-shield-theme')
    return stored === 'light' ? 'light' : 'dark'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('scam-shield-theme', theme)
  }, [theme])

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }

  if (loading) return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center',
                  justifyContent: 'center', gap: 12, color: '#94a3b8' }}>
      <span className="loader"></span> Loading Scam Shield...
    </div>
  )

  if (!user) return <AuthPage />

  const pages = {
    dashboard: <Dashboard setPage={setPage} />,
    detect:    <Detection />,
    alerts:    <Alerts />,
    reports:   <Reports />,
  }

  return (
    <div className="grid-bg app-shell">
      <Sidebar page={page} setPage={setPage} theme={theme} onToggleTheme={toggleTheme} />
      <main className="app-main">
        {pages[page] || <Dashboard setPage={setPage} />}
      </main>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}
