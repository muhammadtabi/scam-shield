import { useState } from 'react'
import { useAuth } from '../../hooks/useAuth'

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
          Create your free account
        </p>
      </div>

      <div className="glass" style={{ padding: 32 }}>
        <h2 style={{ fontFamily: 'Syne', fontWeight: 700, fontSize: 20,
                     marginBottom: 24, color: '#e2e8f0' }}>
          Create Account
        </h2>

        {error && (
          <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
                        borderRadius: 8, padding: '10px 14px', marginBottom: 16,
                        color: '#ef4444', fontSize: 14 }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {[
            { key: 'full_name', label: 'Full Name',       type: 'text',     placeholder: 'Muhammad Tayyaab' },
            { key: 'email',     label: 'Email',           type: 'email',    placeholder: 'your@email.com' },
            { key: 'password',  label: 'Password',        type: 'password', placeholder: '••••••••' },
            { key: 'confirm',   label: 'Confirm Password',type: 'password', placeholder: '••••••••' },
          ].map(f => (
            <div key={f.key} style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 13, color: '#94a3b8',
                              marginBottom: 6, fontWeight: 500 }}>{f.label}</label>
              <input
                className="cyber-input"
                type={f.type}
                placeholder={f.placeholder}
                value={form[f.key]}
                onChange={e => setForm({ ...form, [f.key]: e.target.value })}
                required
              />
            </div>
          ))}

          <button className="btn-cyber" type="submit"
            style={{ width: '100%', marginTop: 8, display: 'flex',
                     alignItems: 'center', justifyContent: 'center', gap: 8 }}
            disabled={loading}>
            {loading ? <><span className="loader" style={{borderTopColor:'#020817'}}></span> Creating...</> : 'Create Account →'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 20, fontSize: 14, color: '#94a3b8' }}>
          Already have an account?{' '}
          <button onClick={onSwitch}
            style={{ background: 'none', border: 'none', color: '#00d4ff',
                     cursor: 'pointer', fontWeight: 600 }}>
            Login
          </button>
        </p>
      </div>
    </div>
  )
}
