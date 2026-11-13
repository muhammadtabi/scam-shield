import { useState } from 'react'
import { useAuth } from '../../hooks/useAuth'
import { Shield, LogIn, AlertCircle } from 'lucide-react'

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
    <div style={{ width: '100%', maxWidth: 380 }}>
      {/* Brand Header */}
      <div style={{ textAlign: 'center', marginBottom: 28 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 'var(--radius-md)',
          background: 'rgba(59, 130, 246, 0.1)',
          border: '1px solid rgba(59, 130, 246, 0.22)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          margin: '0 auto 12px', color: 'var(--accent-primary)'
        }}>
          <Shield size={22} strokeWidth={2.2} />
        </div>
        <h1 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 800, fontSize: 22,
                     color: 'var(--text-primary)', letterSpacing: '-0.025em' }}>
          Scam Shield
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 3 }}>
          Threat detection and security monitoring
        </p>
      </div>

      <div className="card" style={{ padding: '24px 22px' }}>
        <h2 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 17,
                     marginBottom: 16, color: 'var(--text-primary)', letterSpacing: '-0.015em' }}>
          Sign In
        </h2>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)',
                        borderRadius: 'var(--radius-sm)', padding: '9px 12px', marginBottom: 14,
                        color: 'var(--accent-red)', fontSize: 12.5, display: 'flex', alignItems: 'center', gap: 7 }}>
            <AlertCircle size={14} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', fontSize: 12.5, color: 'var(--text-secondary)',
                            marginBottom: 5, fontWeight: 500 }}>Email Address</label>
            <input
              className="input-field"
              type="email"
              placeholder="name@company.com"
              value={form.email}
              onChange={e => setForm({ ...form, email: e.target.value })}
              required
            />
          </div>

          <div style={{ marginBottom: 18 }}>
            <label style={{ display: 'block', fontSize: 12.5, color: 'var(--text-secondary)',
                            marginBottom: 5, fontWeight: 500 }}>Password</label>
            <input
              className="input-field"
              type="password"
              placeholder="••••••••"
              value={form.password}
              onChange={e => setForm({ ...form, password: e.target.value })}
              required
            />
          </div>

          <button className="btn-primary" type="submit"
            style={{ width: '100%', padding: '10px 16px' }}
            disabled={loading}>
            {loading ? (
              <>
                <span className="loader" style={{ borderTopColor: '#ffffff' }}></span>
                <span>Signing in...</span>
              </>
            ) : (
              <>
                <LogIn size={14} />
                <span>Sign In</span>
              </>
            )}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 16, fontSize: 12.5, color: 'var(--text-secondary)' }}>
          Don't have an account?{' '}
          <button onClick={onSwitch}
            type="button"
            style={{ background: 'none', border: 'none', color: 'var(--accent-primary)',
                     cursor: 'pointer', fontWeight: 600 }}>
            Create one
          </button>
        </p>
      </div>
    </div>
  )
}
