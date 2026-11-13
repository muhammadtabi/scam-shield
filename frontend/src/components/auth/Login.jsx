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
    <div style={{ width: '100%', maxWidth: 400 }}>
      {/* Brand Header */}
      <div style={{ textAlign: 'center', marginBottom: 32 }}>
        <div style={{
          width: 52, height: 52, borderRadius: 12,
          background: 'rgba(37, 99, 235, 0.1)',
          border: '1px solid rgba(37, 99, 235, 0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          margin: '0 auto 14px', color: 'var(--accent-cyan)'
        }}>
          <Shield size={26} strokeWidth={2.2} />
        </div>
        <h1 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 800, fontSize: 24,
                     color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
          Scam Shield
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>
          Threat detection and security monitoring
        </p>
      </div>

      <div className="glass" style={{ padding: '28px 26px' }}>
        <h2 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 18,
                     marginBottom: 20, color: 'var(--text-primary)' }}>
          Sign In
        </h2>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)',
                        borderRadius: 8, padding: '10px 14px', marginBottom: 16,
                        color: 'var(--accent-red)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertCircle size={15} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 13, color: 'var(--text-secondary)',
                            marginBottom: 6, fontWeight: 500 }}>Email Address</label>
            <input
              className="input-field"
              type="email"
              placeholder="name@company.com"
              value={form.email}
              onChange={e => setForm({ ...form, email: e.target.value })}
              required
            />
          </div>

          <div style={{ marginBottom: 22 }}>
            <label style={{ display: 'block', fontSize: 13, color: 'var(--text-secondary)',
                            marginBottom: 6, fontWeight: 500 }}>Password</label>
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
            style={{ width: '100%', padding: '11px 16px' }}
            disabled={loading}>
            {loading ? (
              <>
                <span className="loader" style={{ borderTopColor: '#ffffff' }}></span>
                <span>Signing in...</span>
              </>
            ) : (
              <>
                <LogIn size={15} />
                <span>Sign In</span>
              </>
            )}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 18, fontSize: 13, color: 'var(--text-secondary)' }}>
          Don't have an account?{' '}
          <button onClick={onSwitch}
            type="button"
            style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)',
                     cursor: 'pointer', fontWeight: 600 }}>
            Create one
          </button>
        </p>
      </div>
    </div>
  )
}
