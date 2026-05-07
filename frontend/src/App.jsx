import { useState } from 'react'
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
    <div className="grid-bg" style={{
      minHeight: '100vh', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
      padding: 24, position: 'relative'
    }}>
      {/* Glow effect */}
      <div style={{
        position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
        width: 600, height: 600, borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(0,212,255,0.06) 0%, transparent 70%)',
        pointerEvents: 'none'
      }} />
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
    <div className="grid-bg" style={{ minHeight: '100vh', display: 'flex' }}>
      <Sidebar page={page} setPage={setPage} />
      <main style={{ marginLeft: 240, flex: 1, padding: '32px 40px',
                     maxWidth: 'calc(100vw - 240px)' }}>
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
