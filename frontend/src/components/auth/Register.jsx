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
    <div style={{ width: '100%', maxWidth: 400 }}>
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
          Create an account to monitor and detect threats
        </p>
      </div>

      <div className="card" style={{ padding: '24px 22px' }}>
        <h2 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 17,
                     marginBottom: 16, color: 'var(--text-primary)', letterSpacing: '-0.015em' }}>
          Create Account
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
          {[
            { key: 'full_name', label: 'Full Name',       type: 'text',     placeholder: 'Alex Morgan' },
            { key: 'email',     label: 'Email Address',   type: 'email',    placeholder: 'name@company.com' },
            { key: 'password',  label: 'Password',        type: 'password', placeholder: '••••••••' },
            { key: 'confirm',   label: 'Confirm Password',type: 'password', placeholder: '••••••••' },
          ].map(f => (
            <div key={f.key} style={{ marginBottom: 12 }}>
              <label style={{ display: 'block', fontSize: 12.5, color: 'var(--text-secondary)',
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
            style={{ width: '100%', marginTop: 6, padding: '10px 16px' }}
            disabled={loading}>
            {loading ? (
              <>
                <span className="loader" style={{ borderTopColor: '#ffffff' }}></span>
                <span>Creating account...</span>
              </>
            ) : (
              <>
                <UserPlus size={14} />
                <span>Create Account</span>
              </>
            )}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 16, fontSize: 12.5, color: 'var(--text-secondary)' }}>
          Already have an account?{' '}
          <button onClick={onSwitch}
            type="button"
            style={{ background: 'none', border: 'none', color: 'var(--accent-primary)',
                     cursor: 'pointer', fontWeight: 600 }}>
            Sign In
          </button>
        </p>
      </div>
    </div>
  )
}
