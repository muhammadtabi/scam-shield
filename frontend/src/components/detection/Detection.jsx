import { useState } from 'react'
import { api } from '../../api/client'

const TABS = [
  { id: 'email', label: '📧 Email',    desc: '' },
  { id: 'sms',   label: '📱 SMS/Call', desc: 'Detect spam messages' },
  { id: 'url',   label: '🔗 URL',      desc: 'Check malicious links' },
]

const ResultCard = ({ result }) => {
  if (result?.error) {
    return (
      <div className="fade-in" style={{
        background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)',
        borderRadius: 12, padding: 24, marginTop: 24
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 32 }}>⚠️</span>
          <div>
            <div style={{ fontFamily: 'Syne', fontWeight: 800, fontSize: 22, color: '#ef4444' }}>
              Detection Error
            </div>
            <div style={{ color: '#94a3b8', fontSize: 13 }}>
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
    scam:       { bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.3)',  color: '#ef4444', icon: '🚨' },
    suspicious: { bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.3)', color: '#f59e0b', icon: '⚠️' },
    safe:       { bg: 'rgba(34,197,94,0.08)',  border: 'rgba(34,197,94,0.3)',  color: '#22c55e', icon: '✅' },
  }
  const c = colors[scamLevel] || colors.safe

  return (
    <div className="fade-in" style={{
      background: c.bg, border: `1px solid ${c.border}`,
      borderRadius: 12, padding: 24, marginTop: 24
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <span style={{ fontSize: 32 }}>{c.icon}</span>
        <div>
          <div style={{ fontFamily: 'Syne', fontWeight: 800, fontSize: 22, color: c.color }}>
            {scamLevel.toUpperCase()}
          </div>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>
            {confidence}% confidence
          </div>
        </div>
        <div style={{ flex: 1, marginLeft: 16 }}>
          <div style={{ height: 8, background: 'rgba(255,255,255,0.05)',
                        borderRadius: 4, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 4, background: c.color,
              width: `${Math.min(Math.max(confidence, 0), 100)}%`, transition: 'width 1s ease'
            }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between',
                        fontSize: 11, color: '#475569', marginTop: 4,
                        fontFamily: 'Space Mono' }}>
            <span>0%</span><span>50%</span><span>100%</span>
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0',
                      marginBottom: 8 }}>🔍 Detection Reasons:</div>
        {reasons.map((r, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'flex-start', gap: 8,
            padding: '6px 0', fontSize: 13, color: '#94a3b8',
            borderBottom: '1px solid rgba(255,255,255,0.04)'
          }}>
            <span style={{ color: c.color, marginTop: 1 }}>›</span>
            {r}
          </div>
        ))}
      </div>

      {result.explanation && (
        <div style={{
          background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.15)',
          borderRadius: 8, padding: 12
        }}>
          <div style={{ fontSize: 12, color: '#00d4ff', fontWeight: 600,
                        marginBottom: 4, fontFamily: 'Space Mono' }}>
            🤖 AI EXPLANATION
          </div>
          <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>
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

  // 1. Try standard header parsing (e.g. From: / Subject: format)
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
      // Hit regular text, stop parsing headers
      bodyStartIndex = i
      break
    }
  }

  // 2. If standard parsing didn't find headers, try heuristic UI-paste parsing (like Gmail UI)
  if (!subject && !sender) {
    for (let i = 0; i < Math.min(40, lines.length); i++) {
      const line = lines[i].trim()
      const lower = line.toLowerCase()

      // The subject is usually right before "Inbox" or "Important" in a UI copy-paste
      if ((lower === 'inbox' || lower === 'important') && i > 0 && !subject) {
        // Walk backwards to find the nearest non-blank line
        let j = i - 1
        while (j >= 0 && !lines[j].trim()) j--;
        if (j >= 0) subject = lines[j].trim()
      }

      // The sender line typically contains an email address (often with < >)
      if (!sender) {
        const emailMatch = line.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/)
        if (emailMatch && !lower.startsWith('to:')) {
          sender = emailMatch[1]
          bodyStartIndex = i + 1
          
          // Skip the common Gmail UI clutter directly after the sender (dates, "to me")
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
      
      // Stop heuristic search if we found both
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

  // Alphanumeric sender IDs are common in many countries (e.g. BANKALERT, VK-ICICIB).
  if (/[A-Za-z]/.test(compact)) {
    return /^[A-Za-z][A-Za-z0-9_-]{2,19}$/.test(compact)
  }

  // Numeric sender values must be full 11-digit phone numbers.
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
          setError('Please enter a valid sender: exactly 11-digit number (e.g., 03315123456) or sender ID like BANKALERT.')
        } else {
          setError('Please enter SMS message content to analyze.')
        }
      } else if (tab === 'url') {
        setError('Please enter a valid URL only (e.g., example.com or https://example.com). Do not paste SMS/email text here.')
      } else {
        setError('Please paste complete email content to analyze.')
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
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontFamily: 'Syne', fontWeight: 800, fontSize: 28,
                     color: '#e2e8f0', marginBottom: 6 }}>Scan Now</h1>
        <p style={{ color: '#94a3b8', fontSize: 14 }}>
          Analyze emails, SMS messages, or URLs for scams
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => handleTabSwitch(t.id)}
            style={{
              padding: '10px 20px', borderRadius: 10, border: 'none', cursor: 'pointer',
              fontFamily: 'Syne', fontWeight: 600, fontSize: 14, transition: 'all 0.2s',
              background: tab === t.id
                ? 'linear-gradient(135deg, #00d4ff, #0ea5e9)'
                : 'rgba(13,31,60,0.8)',
              color: tab === t.id ? '#020817' : '#94a3b8',
              boxShadow: tab === t.id ? '0 4px 15px rgba(0,212,255,0.3)' : 'none'
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Form */}
      <form className="glass" style={{ padding: 28 }} onSubmit={handleFormSubmit}>
        <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 20 }}>
          {TABS.find(t => t.id === tab)?.desc}
        </p>

        {error && (
          <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
                        borderRadius: 8, padding: '10px 14px', marginBottom: 16,
                        color: '#ef4444', fontSize: 14 }}>
            {error}
          </div>
        )}

        {/* ── EMAIL TAB ── */}
        {tab === 'email' && (
          <div>
            {/* Single paste box */}
            <label style={{ display: 'block', fontSize: 13, color: '#94a3b8',
                            marginBottom: 6, fontWeight: 500 }}>
              Paste Complete Email Here
            </label>
            <textarea
              className="cyber-input"
              placeholder={`From: sender@example.com\nSubject: Your email subject here\n\nPaste the full email content here...\n\n(Or just paste any suspicious text and we'll analyze it!)`}
              rows={10}
              style={{ resize: 'vertical', fontFamily: 'DM Sans', lineHeight: 1.6 }}
              value={rawEmail}
              onChange={e => handleEmailChange(e.target.value)}
              onKeyDown={handleEnterSubmit}
            />

            {/* Live parsed preview */}
            {parsed && rawEmail.trim() && (
              <div style={{
                marginTop: 12, padding: 14, borderRadius: 8,
                background: 'rgba(34,197,94,0.05)',
                border: '1px solid rgba(34,197,94,0.15)'
              }}>
                <div style={{ fontSize: 12, color: '#22c55e', fontWeight: 600,
                              marginBottom: 8, fontFamily: 'Space Mono' }}>
                  ✅ EMAIL PARSED SUCCESSFULLY
                </div>
                <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 3 }}>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>From: </span>
                  {parsed.sender || 'Not specified'}
                </div>
                <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 3 }}>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>Subject: </span>
                  {parsed.subject || 'Not specified'}
                </div>
                <div style={{ fontSize: 12, color: '#94a3b8' }}>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>Body: </span>
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
              <label style={{ display: 'block', fontSize: 13, color: '#94a3b8',
                              marginBottom: 6, fontWeight: 500 }}>Sender Number or ID</label>
              <input className="cyber-input" placeholder="+1 415 555 0199 or BANKALERT"
                type="tel"
                value={smsForm.sender_id}
                onChange={e => setSmsForm({ ...smsForm, sender_id: e.target.value })}
                onKeyDown={handleEnterSubmit} />
              {smsForm.sender_id.trim() && !isValidSmsSender(smsForm.sender_id) && (
                <p style={{ fontSize: 12, color: '#ef4444', marginTop: 6 }}>
                  Enter a valid sender: exactly 11-digit number (e.g., 03315123456) or sender ID (example: BANKALERT)
                </p>
              )}
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 13, color: '#94a3b8',
                              marginBottom: 6, fontWeight: 500 }}>Message Content</label>
              <textarea className="cyber-input"
                placeholder="Paste the SMS or call description here..."
                rows={5} style={{ resize: 'vertical', fontFamily: 'DM Sans' }}
                value={smsForm.message}
                onChange={e => setSmsForm({ ...smsForm, message: e.target.value })}
                onKeyDown={handleEnterSubmit} />
            </div>
          </div>
        )}

        {/* ── URL TAB ── */}
        {tab === 'url' && (
          <div>
            <label style={{ display: 'block', fontSize: 13, color: '#94a3b8',
                            marginBottom: 6, fontWeight: 500 }}>URL to Analyze</label>
            <input className="cyber-input"
              placeholder="https://suspicious-website.xyz/login"
              value={urlForm.url}
              onChange={e => setUrlForm({ url: e.target.value })}
              onKeyDown={handleEnterSubmit} />
            <p style={{ fontSize: 12, color: '#475569', marginTop: 8 }}>
              Tip: Paste any URL — phishing links, suspicious websites, unknown domains
            </p>
          </div>
        )}

        <button className="btn-cyber"
          type="submit"
          disabled={loading || !canSubmit()}
          style={{
            marginTop: 24, display: 'flex', alignItems: 'center',
            gap: 8, padding: '12px 28px',
            opacity: canSubmit() ? 1 : 0.5,
            cursor: canSubmit() ? 'pointer' : 'not-allowed'
          }}>
          {loading
            ? <><span className="loader" style={{ borderTopColor: '#020817' }}></span> Analyzing...</>
            : '⚡ Analyze Now'}
        </button>

        {!canSubmit() && (
          <p style={{ fontSize: 12, color: '#475569', marginTop: 8 }}>
            ⚠️ Please paste content above to enable analysis
          </p>
        )}
      </form>

      {result && <ResultCard result={result} />}
    </div>
  )
}