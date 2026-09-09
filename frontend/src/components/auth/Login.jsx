import { useState } from 'react'
import { useAuth } from '../../hooks/useAuth'

export default function Login({ onSwitch }) {
  const { login } = useAuth()
  const [form,    setForm]    = useState({ email: '', password: '' })
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await login(form.email, form.password)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ width: '100%', maxWidth: 420 }}>
      {/* Logo */}
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <div style={{
          width: 64, height: 64, borderRadius: 16,
          background: 'linear-gradient(135deg, #00d4ff22, #0ea5e922)',
          border: '1px solid rgba(0,212,255,0.3)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          margin: '0 auto 16px', fontSize: 28
        }}>🛡️</div>
        <h1 style={{ fontFamily: 'Syne', fontWeight: 800, fontSize: 28,
                     background: 'linear-gradient(135deg, #00d4ff, #0ea5e9)',
                     WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          Scam Shield
        </h1>
        <p style={{ color: '#94a3b8', fontSize: 14, marginTop: 6 }}>
          AI-Powered Scam Detection
        </p>
      </div>

      <div className="glass" style={{ padding: 32 }}>
        <h2 style={{ fontFamily: 'Syne', fontWeight: 700, fontSize: 20,
                     marginBottom: 24, color: '#e2e8f0' }}>
          Login to Your Account
        </h2>

        {error && (
          <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
                        borderRadius: 8, padding: '10px 14px', marginBottom: 16,
                        color: '#ef4444', fontSize: 14 }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 13, color: '#94a3b8',
                            marginBottom: 6, fontWeight: 500 }}>Email</label>
            <input
              className="cyber-input"
              type="email"
              placeholder="your@email.com"
              value={form.email}
              onChange={e => setForm({ ...form, email: e.target.value })}
              required
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={{ display: 'block', fontSize: 13, color: '#94a3b8',
                            marginBottom: 6, fontWeight: 500 }}>Password</label>
            <input
              className="cyber-input"
              type="password"
              placeholder="••••••••"
              value={form.password}
              onChange={e => setForm({ ...form, password: e.target.value })}
              required
            />
          </div>

          <button className="btn-cyber" type="submit"
            style={{ width: '100%', display: 'flex', alignItems: 'center',
                     justifyContent: 'center', gap: 8 }}
            disabled={loading}>
            {loading ? <><span className="loader" style={{borderTopColor:'#020817'}}></span> Logging in...</> : 'Login →'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 20, fontSize: 14, color: '#94a3b8' }}>
          Don't have an account?{' '}
          <button onClick={onSwitch}
            style={{ background: 'none', border: 'none', color: '#00d4ff',
                     cursor: 'pointer', fontWeight: 600 }}>
            Sign Up
          </button>
        </p>
      </div>
    </div>
  )
}
