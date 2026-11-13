import { useState } from 'react'
import { Mail, RefreshCw, LogOut, KeyRound, ExternalLink } from 'lucide-react'

export default function GmailConnect({
  gmail,
  busy,
  error,
  onConnect,
  onConnectImap,
  onSync,
  onRefresh,
  onDisconnect,
}) {
  const [showImapForm, setShowImapForm] = useState(false)
  const [provider, setProvider] = useState('gmail')
  const [email, setEmail] = useState('')
  const [appPassword, setAppPassword] = useState('')
  const [localError, setLocalError] = useState('')

  const handleImapSubmit = async (e) => {
    e.preventDefault()
    setLocalError('')
    const trimmedEmail = email.trim()
    const compactPassword = appPassword.replace(/\s+/g, '')

    if (!trimmedEmail || !trimmedEmail.includes('@')) {
      setLocalError('Please enter a valid email address.')
      return
    }
    if (compactPassword.length < 8) {
      setLocalError('Please enter your App Password (at least 8 characters).')
      return
    }

    const ok = await onConnectImap?.({
      email: trimmedEmail,
      app_password: compactPassword,
      provider,
    })
    if (ok) {
      setAppPassword('')
      setShowImapForm(false)
    }
  }

  const displayedError = localError || error

  return (
    <div className="glass stagger stagger-3 gmail-connect-panel">
      <div className="gmail-connect-copy">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Mail size={16} color="var(--accent-cyan)" />
          <div className="panel-title">Email Monitor</div>
        </div>
        <div className="panel-subtitle">
          {gmail?.connected
            ? gmail.auth_type === 'imap'
              ? `Watching ${gmail.email_address || 'your inbox'} via read-only IMAP`
              : `Watching ${gmail.email_address || 'your inbox'} for new mail`
            : 'Connect with Google OAuth or a read-only App Password'}
        </div>
        {gmail?.last_checked_at && (
          <div className="panel-meta">
            Last checked: {new Date(gmail.last_checked_at).toLocaleString()}
          </div>
        )}
        {displayedError && (
          <div className="gmail-connect-error" role="alert">
            {displayedError}
          </div>
        )}

        {!gmail?.connected && showImapForm && (
          <form className="imap-connect-form" onSubmit={handleImapSubmit}>
            <p className="imap-connect-help">
              Read-only TLS connection (INBOX read-only). For Gmail, enable 2-Step Verification and generate a 16-character{' '}
              <a
                href="https://myaccount.google.com/apppasswords"
                target="_blank"
                rel="noreferrer noopener"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}
              >
                <span>Google App Password</span>
                <ExternalLink size={11} />
              </a>
              {' '}(never enter your main Google password).
            </p>
            <div className="imap-connect-row">
              <select
                className="input-field imap-provider-select"
                aria-label="Email Provider"
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                disabled={busy}
              >
                <option value="gmail">Gmail / Google Workspace</option>
                <option value="outlook">Outlook / Hotmail</option>
                <option value="yahoo">Yahoo Mail</option>
                <option value="zoho">Zoho Mail</option>
              </select>
              <input
                className="input-field"
                type="email"
                placeholder="you@gmail.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={busy}
                required
              />
              <input
                className="input-field"
                type="password"
                placeholder="16-character App Password"
                autoComplete="off"
                value={appPassword}
                onChange={(e) => setAppPassword(e.target.value)}
                disabled={busy}
                required
              />
            </div>
            <div className="imap-connect-actions">
              <button type="submit" className="btn-primary" disabled={busy} style={{ padding: '7px 14px', fontSize: 13 }}>
                {busy ? 'Verifying...' : 'Connect Read-Only'}
              </button>
              <button
                type="button"
                className="gmail-secondary-button"
                disabled={busy}
                onClick={() => {
                  setShowImapForm(false)
                  setLocalError('')
                  setAppPassword('')
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      <div className="gmail-connect-actions">
        {gmail?.connected ? (
          <>
            <button className="btn-primary" onClick={onSync} disabled={busy} style={{ padding: '7px 14px', fontSize: 13 }}>
              <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
              <span>{busy ? 'Syncing...' : 'Sync Now'}</span>
            </button>
            <button className="gmail-secondary-button" onClick={onRefresh} disabled={busy}>
              Refresh
            </button>
            <button className="gmail-danger-button" onClick={onDisconnect} disabled={busy}>
              Disconnect
            </button>
          </>
        ) : (
          <>
            <button className="btn-primary" onClick={onConnect} disabled={busy} style={{ padding: '7px 14px', fontSize: 13 }}>
              <Mail size={14} />
              <span>{busy ? 'Connecting...' : 'Connect Gmail'}</span>
            </button>
            {onConnectImap && (
              <button
                type="button"
                className="gmail-secondary-button"
                disabled={busy}
                onClick={() => {
                  setLocalError('')
                  setShowImapForm((prev) => !prev)
                }}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <KeyRound size={13} />
                <span>{showImapForm ? 'Hide App Password' : 'Use App Password'}</span>
              </button>
            )}
          </>
        )}
      </div>
    </div>
  )
}
