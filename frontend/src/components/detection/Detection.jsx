import { useState } from 'react'
import { api } from '../../api/client'
import {
  Mail,
  MessageSquare,
  Link2,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  AlertCircle,
  Search,
  CheckCircle2,
  Info,
  ChevronRight
} from 'lucide-react'

const TABS = [
  { id: 'email', label: 'Email', icon: Mail,          desc: 'Inspect email headers, sender domains, and message bodies' },
  { id: 'sms',   label: 'SMS',   icon: MessageSquare, desc: 'Scan SMS messages for fraud, sender spoofing, and smishing' },
  { id: 'url',   label: 'URL',   icon: Link2,          desc: 'Inspect URLs for phishing, spoofing, and suspicious redirects' },
]

const ResultCard = ({ result }) => {
  if (result?.error) {
    return (
      <div className="fade-in glass" style={{
        background: 'rgba(239, 68, 68, 0.08)',
        borderColor: 'rgba(239, 68, 68, 0.25)',
        padding: 22, marginTop: 20
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <AlertCircle size={28} color="var(--accent-red)" />
          <div>
            <div style={{ fontFamily: 'Plus Jakarta Sans, sans-serif', fontWeight: 700, fontSize: 18, color: 'var(--accent-red)' }}>
              Detection Error
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 2 }}>
              {result.error}
            </div>
          </div>
        </div>
      </div>
    )
  }

  const scamLevel = result?.scam_level || 'safe'
  const confidence = Number.isFinite(Number(result?.confidence)) ? Number(result.confidence) : 0
  const reasons = Array.isArray(result?.reasons) ? result.reasons : []

  const colors = {
    scam:       { bg: 'rgba(239, 68, 68, 0.08)',  border: 'rgba(239, 68, 68, 0.25)',  color: 'var(--accent-red)',    Icon: ShieldAlert },
    suspicious: { bg: 'rgba(245, 158, 11, 0.08)', border: 'rgba(245, 158, 11, 0.25)', color: 'var(--accent-yellow)', Icon: AlertTriangle },
    safe:       { bg: 'rgba(16, 185, 129, 0.08)', border: 'rgba(16, 185, 129, 0.25)', color: 'var(--accent-green)',  Icon: ShieldCheck },
  }
  const c = colors[scamLevel] || colors.safe
  const VerdictIcon = c.Icon

  return (
    <div className="fade-in glass" style={{
      background: c.bg, borderColor: c.border,
      padding: 24, marginTop: 24
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 18 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 10,
          background: 'var(--bg-card)',
          border: `1px solid ${c.border}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: c.color, flexShrink: 0
        }}>
          <VerdictIcon size={24} strokeWidth={2.2} />
        </div>
        <div>
          <div style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 800, fontSize: 20, color: c.color, letterSpacing: '0.02em' }}>
            {scamLevel.toUpperCase()}
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: 13, fontFamily: 'JetBrains Mono' }}>
            {confidence}% confidence score
          </div>
        </div>
        <div style={{ flex: 1, marginLeft: 16 }}>
          <div style={{ height: 6, background: 'var(--bg-secondary)',
                        borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 3, background: c.color,
              width: `${Math.min(Math.max(confidence, 0), 100)}%`, transition: 'width 0.6s ease'
            }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between',
                        fontSize: 10, color: 'var(--text-muted)', marginTop: 4,
                        fontFamily: 'JetBrains Mono' }}>
            <span>0%</span><span>50%</span><span>100%</span>
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 18 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)',
                      marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
          <CheckCircle2 size={14} color={c.color} />
          <span>Detection Factors:</span>
        </div>
        {reasons.map((r, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'flex-start', gap: 8,
            padding: '6px 0', fontSize: 13, color: 'var(--text-secondary)',
            borderBottom: '1px solid var(--border-subtle)'
          }}>
            <ChevronRight size={14} color={c.color} style={{ marginTop: 2, flexShrink: 0 }} />
            <span>{r}</span>
          </div>
        ))}
      </div>

      {result.explanation && (
        <div style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: 14
        }}>
          <div style={{ fontSize: 11, color: 'var(--accent-cyan)', fontWeight: 700,
                        marginBottom: 4, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
            <Info size={12} />
            <span>EXPLANATION</span>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {result.explanation}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Auto parse raw email text ──────────────────────────────
const parseRawEmail = (raw) => {
  const lines = raw.split('\n')
  let subject = ''
  let sender  = ''
  let bodyStartIndex = -1

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const lower = line.toLowerCase()

    if (lower.startsWith('from:') || lower.startsWith('from :')) {
      sender = line.replace(/^from\s*:/i, '').trim()
      const match = sender.match(/<(.+?)>/)
      if (match) sender = match[1]
    } else if (lower.startsWith('subject:') || lower.startsWith('subject :')) {
      subject = line.replace(/^subject\s*:/i, '').trim()
    } else if (line.trim() === '' && (subject || sender)) {
      bodyStartIndex = i + 1
      break
    } else if (!lower.startsWith('to:') && !lower.startsWith('date:') &&
               !lower.startsWith('cc:') && !lower.startsWith('bcc:') &&
               !lower.startsWith('reply-to:') && !lower.startsWith('message-id:') &&
               (subject || sender)) {
      bodyStartIndex = i
      break
    }
  }

  if (!subject && !sender) {
    for (let i = 0; i < Math.min(40, lines.length); i++) {
      const line = lines[i].trim()
      const lower = line.toLowerCase()

      if ((lower === 'inbox' || lower === 'important') && i > 0 && !subject) {
        let j = i - 1
        while (j >= 0 && !lines[j].trim()) j--;
        if (j >= 0) subject = lines[j].trim()
      }

      if (!sender) {
        const emailMatch = line.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/)
        if (emailMatch && !lower.startsWith('to:')) {
          sender = emailMatch[1]
          bodyStartIndex = i + 1
          
          for (let k = 0; k < 4; k++) {
            if (bodyStartIndex < lines.length) {
              const nextLine = lines[bodyStartIndex].trim().toLowerCase()
              if (nextLine === 'to me' || nextLine.includes('ago)') || nextLine.match(/^\w{3}, \w{3} \d{1,2}, \d{1,2}:\d{2}/) || !nextLine) {
                bodyStartIndex++
              } else {
                break
              }
            }
          }
        }
      }
      
      if (subject && sender) break
    }
  }

  let parsedBody = ''
  if (bodyStartIndex >= 0 && bodyStartIndex < lines.length) {
    parsedBody = lines.slice(bodyStartIndex).join('\n').trim()
  }

  return {
    subject: subject || '',
    sender:  sender  || '',
    body:    parsedBody || raw.trim()
  }
}

const isValidSmsSender = (sender) => {
  const value = sender.trim()
  if (!value) return false

  const compact = value.replace(/\s+/g, '')
  if (compact.length < 3 || compact.length > 20) return false

  if (/[A-Za-z]/.test(compact)) {
    return /^[A-Za-z][A-Za-z0-9_-]{2,19}$/.test(compact)
  }

  if (/^\d{4,6}$/.test(compact)) return true

  if (!/^[+\d\s().-]+$/.test(value)) return false
  const digitsOnly = value.replace(/\D/g, '')
  return digitsOnly.length === 11
}

const isLikelyUrlInput = (value) => {
  const raw = value.trim()
  if (!raw || /\s/.test(raw)) return false

  const normalized = /^(https?:\/\/|ftp:\/\/)/i.test(raw) ? raw : `http://${raw}`

  try {
    const parsed = new URL(normalized)
    const host = parsed.hostname?.toLowerCase() || ''
    const isDomain = /^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(host)
    const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)
    return isDomain || isIPv4
  } catch {
    return false
  }
}

export default function Detection() {
  const [tab,      setTab]      = useState('email')
  const [loading,  setLoading]  = useState(false)
  const [result,   setResult]   = useState(null)
  const [error,    setError]    = useState('')
  const [rawEmail, setRawEmail] = useState('')
  const [parsed,   setParsed]   = useState(null)
  const [smsForm,  setSmsForm]  = useState({ sender_id: '', message: '' })
  const [urlForm,  setUrlForm]  = useState({ url: '' })

  const handleTabSwitch = (newTab) => {
    setTab(newTab)
    setResult(null)
    setError('')
    setRawEmail('')
    setParsed(null)
    setSmsForm({ sender_id: '', message: '' })
    setUrlForm({ url: '' })
  }

  const handleEmailChange = (val) => {
    setRawEmail(val)
    setResult(null)
    if (val.trim()) {
      setParsed(parseRawEmail(val))
    } else {
      setParsed(null)
    }
  }

  const handleDetect = async () => {
    if (!canSubmit()) {
      if (tab === 'sms') {
        if (!smsForm.sender_id.trim()) {
          setError('Please enter sender number or sender ID.')
        } else if (!isValidSmsSender(smsForm.sender_id)) {
          setError('Please enter an 11-digit number (e.g., 03315123456), 4-6 digit shortcode (e.g., 8558), or sender ID like BANKALERT.')
        } else {
          setError('Please enter SMS message content to analyze.')
        }
      } else if (tab === 'url') {
        setError('Please enter a valid URL only (e.g., example.com or https://example.com). Do not paste SMS/email text here.')
      } else {
        setError('Please paste email content to analyze.')
      }
      return
    }
    setLoading(true); setError(''); setResult(null)
    try {
      let res
      if (tab === 'email') {
        const { subject, sender, body } = parseRawEmail(rawEmail)
        res = await api.detectEmail({ subject, sender, body })
      }
      if (tab === 'sms') res = await api.detectSMS(smsForm)
      if (tab === 'url') res = await api.detectURL(urlForm)
      setResult(res)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleFormSubmit = (e) => {
    e.preventDefault()
    if (!loading) {
      handleDetect()
    }
  }

  const handleEnterSubmit = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      if (!loading) {
        handleDetect()
      }
    }
  }

  const canSubmit = () => {
    if (tab === 'email') return rawEmail.trim().length > 10
    if (tab === 'sms')   return isValidSmsSender(smsForm.sender_id) && smsForm.message.trim().length > 0
    if (tab === 'url') {
      const urlValue = urlForm.url.trim()
      return isLikelyUrlInput(urlValue)
    }
    return false
  }

  return (
    <div className="fade-in">
      <div className="page-header stagger stagger-1">
        <h1 className="page-title">Scan Now</h1>
        <p className="page-subtitle">
          Analyze emails, SMS messages, or URLs for threats
        </p>
      </div>

      <div className="tab-switcher stagger stagger-2">
        {TABS.map(t => {
          const TabIcon = t.icon
          const isActive = tab === t.id
          return (
            <button key={t.id} onClick={() => handleTabSwitch(t.id)}
              className={`tab-btn ${isActive ? 'active' : ''}`}
              type="button"
            >
              <TabIcon size={14} strokeWidth={isActive ? 2.2 : 1.8} />
              <span>{t.label}</span>
            </button>
          )
        })}
      </div>

      <form className="glass stagger stagger-3" style={{ padding: 26 }} onSubmit={handleFormSubmit}>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 18 }}>
          {TABS.find(t => t.id === tab)?.desc}
        </p>

        {error && (
          <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.2)',
                        borderRadius: 8, padding: '10px 14px', marginBottom: 16,
                        color: 'var(--accent-red)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertCircle size={15} />
            <span>{error}</span>
          </div>
        )}

        {/* ── EMAIL TAB ── */}
        {tab === 'email' && (
          <div>
            <label style={{ display: 'block', fontSize: 13, color: 'var(--text-secondary)',
                            marginBottom: 6, fontWeight: 500 }}>
              Email Content
            </label>
            <textarea
              className="input-field"
              placeholder={`From: sender@example.com\nSubject: Account verification\n\nPaste the email content or raw message headers here...`}
              rows={9}
              style={{ resize: 'vertical', lineHeight: 1.6 }}
              value={rawEmail}
              onChange={e => handleEmailChange(e.target.value)}
              onKeyDown={handleEnterSubmit}
            />

            {/* Live parsed preview */}
            {parsed && rawEmail.trim() && (
              <div style={{
                marginTop: 12, padding: 14, borderRadius: 8,
                background: 'rgba(16, 185, 129, 0.06)',
                border: '1px solid rgba(16, 185, 129, 0.2)'
              }}>
                <div style={{ fontSize: 11, color: 'var(--accent-green)', fontWeight: 700,
                              marginBottom: 8, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <CheckCircle2 size={13} />
                  <span>PARSED EMAIL HEADERS</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 3 }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>From: </span>
                  {parsed.sender || 'Not specified'}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 3 }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Subject: </span>
                  {parsed.subject || 'Not specified'}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Body: </span>
                  {parsed.body ? parsed.body.substring(0, 100) : 'Empty'}
                  {parsed.body && parsed.body.length > 100 ? '...' : ''}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── SMS TAB ── */}
        {tab === 'sms' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 13, color: 'var(--text-secondary)',
                              marginBottom: 6, fontWeight: 500 }}>Sender Number or ID</label>
              <input className="input-field" placeholder="+1 415 555 0199, 8558, or BANKALERT"
                type="tel"
                value={smsForm.sender_id}
                onChange={e => setSmsForm({ ...smsForm, sender_id: e.target.value })}
                onKeyDown={handleEnterSubmit} />
              {smsForm.sender_id.trim() && !isValidSmsSender(smsForm.sender_id) && (
                <p style={{ fontSize: 12, color: 'var(--accent-red)', marginTop: 6 }}>
                  Enter an 11-digit number (e.g., 03315123456), 4-6 digit shortcode (e.g., 8558), or sender ID (e.g., BANKALERT)
                </p>
              )}
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 13, color: 'var(--text-secondary)',
                              marginBottom: 6, fontWeight: 500 }}>Message Content</label>
              <textarea className="input-field"
                placeholder="Paste the SMS text here..."
                rows={5} style={{ resize: 'vertical' }}
                value={smsForm.message}
                onChange={e => setSmsForm({ ...smsForm, message: e.target.value })}
                onKeyDown={handleEnterSubmit} />
            </div>
          </div>
        )}

        {/* ── URL TAB ── */}
        {tab === 'url' && (
          <div>
            <label style={{ display: 'block', fontSize: 13, color: 'var(--text-secondary)',
                            marginBottom: 6, fontWeight: 500 }}>URL to Analyze</label>
            <input className="input-field"
              placeholder="https://suspicious-website.xyz/login"
              value={urlForm.url}
              onChange={e => setUrlForm({ url: e.target.value })}
              onKeyDown={handleEnterSubmit} />
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
              Inspect URLs for deceptive domains, abnormal redirects, and known phishing patterns.
            </p>
          </div>
        )}

        <div style={{ marginTop: 22, display: 'flex', alignItems: 'center', gap: 14 }}>
          <button className="btn-primary"
            type="submit"
            disabled={loading || !canSubmit()}
            style={{
              padding: '10px 24px',
              opacity: canSubmit() ? 1 : 0.5,
              cursor: canSubmit() ? 'pointer' : 'not-allowed'
            }}>
            {loading ? (
              <>
                <span className="loader" style={{ borderTopColor: '#ffffff' }}></span>
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Search size={15} />
                <span>Analyze</span>
              </>
            )}
          </button>

          {!canSubmit() && (
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Enter content above to start the scan.
            </span>
          )}
        </div>
      </form>

      {result && <ResultCard result={result} />}
    </div>
  )
}
