import { useState } from 'react'
import { useAuth } from '../../hooks/useAuth'
import { Shield, UserPlus, AlertCircle } from 'lucide-react'

export default function Register({ onSwitch }) {
  const { register } = useAuth()
  const [form,    setForm]    = useState({ full_name: '', email: '', password: '', confirm: '' })
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (form.password !== form.confirm) {
      setError('Passwords do not match'); return
    }
    setLoading(true); setError('')
    try {
      await register(form.full_name, form.email, form.password)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ width: '100%', maxWidth: 420 }}>
      {/* Brand Header */}
      <div style={{ textAlign: 'center', marginBottom: 28 }}>
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
          Create an account to monitor and detect threats
        </p>
      </div>

      <div className="glass" style={{ padding: '26px 24px' }}>
        <h2 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 18,
                     marginBottom: 20, color: 'var(--text-primary)' }}>
          Create Account
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
          {[
            { key: 'full_name', label: 'Full Name',       type: 'text',     placeholder: 'Alex Morgan' },
            { key: 'email',     label: 'Email Address',   type: 'email',    placeholder: 'name@company.com' },
            { key: 'password',  label: 'Password',        type: 'password', placeholder: '••••••••' },
            { key: 'confirm',   label: 'Confirm Password',type: 'password', placeholder: '••••••••' },
          ].map(f => (
            <div key={f.key} style={{ marginBottom: 14 }}>
              <label style={{ display: 'block', fontSize: 13, color: 'var(--text-secondary)',
                              marginBottom: 5, fontWeight: 500 }}>{f.label}</label>
              <input
                className="input-field"
                type={f.type}
                placeholder={f.placeholder}
                value={form[f.key]}
                onChange={e => setForm({ ...form, [f.key]: e.target.value })}
                required
              />
            </div>
          ))}

          <button className="btn-primary" type="submit"
            style={{ width: '100%', marginTop: 8, padding: '11px 16px' }}
            disabled={loading}>
            {loading ? (
              <>
                <span className="loader" style={{ borderTopColor: '#ffffff' }}></span>
                <span>Creating account...</span>
              </>
            ) : (
              <>
                <UserPlus size={15} />
                <span>Create Account</span>
              </>
            )}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 18, fontSize: 13, color: 'var(--text-secondary)' }}>
          Already have an account?{' '}
          <button onClick={onSwitch}
            type="button"
            style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)',
                     cursor: 'pointer', fontWeight: 600 }}>
            Sign In
          </button>
        </p>
      </div>
    </div>
  )
}
