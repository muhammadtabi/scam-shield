import { useEffect, useState, useCallback } from 'react'
import { api } from '../../api/client'
import {
  Smartphone,
  ShieldCheck,
  AlertTriangle,
  ShieldX,
  RefreshCw,
  Trash2,
  ChevronDown,
  ChevronUp,
  Search,
  Copy,
  Check,
  Send,
  Sparkles,
  Info,
  CheckCircle2,
  Upload,
  FileText,
} from 'lucide-react'

const ScamBadge = ({ level, confidence }) => {
  const map = {
    scam: { cls: 'badge-scam', label: 'SCAM', Icon: ShieldX },
    suspicious: { cls: 'badge-suspicious', label: 'SUSPICIOUS', Icon: AlertTriangle },
    safe: { cls: 'badge-safe', label: 'SAFE', Icon: ShieldCheck },
  }
  const b = map[level] || map.safe
  const IconComp = b.Icon
  return (
    <span className={`badge ${b.cls}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      <IconComp size={12} strokeWidth={2.4} />
      <span>{b.label}</span>
      {confidence != null && (
        <span style={{ opacity: 0.85, fontSize: '0.85em' }}>
          ({Math.round(confidence * 100)}%)
        </span>
      )}
    </span>
  )
}

const PRESETS = [
  {
    id: 'bank_otp_safe',
    title: 'Chase Bank OTP',
    type: 'safe',
    desc: 'Official 4-digit bank shortcode (8558) with standard security disclaimer.',
  },
  {
    id: 'carrier_notice_safe',
    title: 'Carrier Auto-Pay Renewal',
    type: 'safe',
    desc: 'Legitimate telecom renewal reminder from carrier shortcode (3737).',
  },
  {
    id: 'package_delivery_scam',
    title: 'USPS Delivery Failure',
    type: 'scam',
    desc: 'Smishing scam with urgency and phishing URL spoofing USPS package tracking.',
  },
  {
    id: 'bank_suspension_scam',
    title: 'Wells Fargo Account Lock',
    type: 'scam',
    desc: 'Account suspension scare tactic with fake verification domain.',
  },
  {
    id: 'lottery_prize_scam',
    title: 'International Lottery Win',
    type: 'scam',
    desc: 'Foreign premium number advance-fee prize fraud asking for bank info.',
  },
  {
    id: 'job_offer_scam',
    title: 'Urgent Remote Job Offer',
    type: 'scam',
    desc: 'Unsolicited high-paying remote job bait redirecting to unknown WhatsApp.',
  },
]

export default function SmsInbox() {
  const [status, setStatus] = useState(null)
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  // Filter & Search states
  const [activeFilter, setActiveFilter] = useState('all') // all, scam, suspicious, safe
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedId, setExpandedId] = useState(null)

  // Phone connection inputs
  const [phoneInput, setPhoneInput] = useState('')
  const [connecting, setConnecting] = useState(false)
  const [copiedToken, setCopiedToken] = useState(false)
  const [copiedCurl, setCopiedCurl] = useState(false)

  // Simulator controls
  const [simulating, setSimulating] = useState(false)
  const [showSimPanel, setShowSimPanel] = useState(false)
  const [customSender, setCustomSender] = useState('')
  const [customMessage, setCustomMessage] = useState('')

  // Batch Import Past SMS controls
  const [showImportPanel, setShowImportPanel] = useState(false)
  const [importInputText, setImportInputText] = useState('')
  const [importing, setImporting] = useState(false)

  const loadData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true)
    else setLoading(true)
    setError('')

    try {
      const statusRes = await api.getSmsStatus()
      setStatus(statusRes)

      const filterParam = activeFilter === 'all' ? null : activeFilter
      const inboxRes = await api.getSmsInbox(filterParam, searchQuery || null)
      setMessages(inboxRes.messages || [])
    } catch (err) {
      setError(err.message || 'Failed to load SMS inbox')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [activeFilter, searchQuery])

  useEffect(() => {
    loadData()
  }, [loadData])

  const handleConnect = async (e) => {
    e.preventDefault()
    if (!phoneInput.trim()) return
    setConnecting(true)
    setError('')
    try {
      const updated = await api.connectSmsPhone(phoneInput.trim())
      setStatus(updated)
      setSuccessMsg(`Phone number ${phoneInput.trim()} connected successfully`)
      setPhoneInput('')
      await loadData(true)
    } catch (err) {
      setError(err.message || 'Failed to connect phone number')
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async () => {
    if (!window.confirm('Disconnect your phone number from SMS monitoring?')) return
    try {
      const res = await api.disconnectSmsPhone()
      setStatus(res)
      setSuccessMsg('Phone disconnected')
      await loadData(true)
    } catch (err) {
      setError(err.message || 'Failed to disconnect phone')
    }
  }

  const handleDeleteMessage = async (id, e) => {
    e.stopPropagation()
    try {
      await api.deleteSmsMessage(id)
      setMessages(prev => prev.filter(m => m.id !== id))
      if (expandedId === id) setExpandedId(null)
    } catch (err) {
      setError(err.message || 'Failed to delete SMS')
    }
  }

  const handleSimulatePreset = async (presetId) => {
    setSimulating(true)
    setError('')
    try {
      const newMsg = await api.simulateSms({ preset: presetId })
      setMessages(prev => [newMsg, ...prev])
      setSuccessMsg(`Simulated message added: ${newMsg.sender_id}`)
      setExpandedId(newMsg.id)
      const updatedStatus = await api.getSmsStatus()
      setStatus(updatedStatus)
    } catch (err) {
      setError(err.message || 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  const handleCustomSimulate = async (e) => {
    e.preventDefault()
    if (!customSender.trim() || !customMessage.trim()) return
    setSimulating(true)
    setError('')
    try {
      const newMsg = await api.simulateSms({
        sender_id: customSender.trim(),
        message: customMessage.trim(),
      })
      setMessages(prev => [newMsg, ...prev])
      setSuccessMsg(`Custom SMS tested and ingested: ${newMsg.sender_id}`)
      setCustomSender('')
      setCustomMessage('')
      setExpandedId(newMsg.id)
      const updatedStatus = await api.getSmsStatus()
      setStatus(updatedStatus)
    } catch (err) {
      setError(err.message || 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  const copySyncToken = () => {
    if (!status?.sync_token) return
    navigator.clipboard.writeText(status.sync_token)
    setCopiedToken(true)
    setTimeout(() => setCopiedToken(false), 2000)
  }

  const copyCurlWebhook = () => {
    if (!status?.sync_token) return
    const cmd = `curl -X POST "http://localhost:8000/api/sms/receive?token=${status.sync_token}" \\
  -H "Content-Type: application/json" \\
  -d '{"sender_id": "8558", "message": "Your verification code is 492011"}'`
    navigator.clipboard.writeText(cmd)
    setCopiedCurl(true)
    setTimeout(() => setCopiedCurl(false), 2000)
  }

  const parseMessagesFromInput = (rawText) => {
    const trimmed = (rawText || '').trim()
    if (!trimmed) return []

    // 1. JSON array format
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try {
        const parsed = JSON.parse(trimmed)
        if (Array.isArray(parsed)) {
          return parsed.map(item => ({
            sender_id: String(item.sender_id || item.sender || item.from || item.address || 'Unknown').trim(),
            message: String(item.message || item.body || item.text || '').trim(),
            timestamp: item.timestamp || item.date || null
          })).filter(m => m.sender_id && m.message)
        }
      } catch {
        // Fall through to regex parsing
      }
    }

    // 2. Android XML Backup format: <sms address="..." body="..." />
    if (trimmed.includes('<sms ') || trimmed.includes('<smses')) {
      const regex = /<sms\s+[^>]*address="([^"]+)"[^>]*body="([^"]+)"[^>]*>/gi
      const matches = []
      let match
      while ((match = regex.exec(trimmed)) !== null) {
        matches.push({
          sender_id: match[1].trim(),
          message: match[2].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim(),
        })
      }
      if (matches.length > 0) return matches
    }

    // 3. Line by line text or CSV
    const lines = trimmed.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
    const results = []
    for (const line of lines) {
      if (line.includes(':')) {
        const idx = line.indexOf(':')
        const s = line.slice(0, idx).trim()
        const m = line.slice(idx + 1).trim()
        if (s && m) {
          results.push({ sender_id: s, message: m })
          continue
        }
      }
      if (line.includes(',')) {
        const idx = line.indexOf(',')
        const s = line.slice(0, idx).trim().replace(/^["']|["']$/g, '')
        const m = line.slice(idx + 1).trim().replace(/^["']|["']$/g, '')
        if (s && m) {
          results.push({ sender_id: s, message: m })
          continue
        }
      }
      results.push({ sender_id: 'Historical SMS', message: line })
    }
    return results
  }

  const handleParseAndImport = async () => {
    const parsed = parseMessagesFromInput(importInputText)
    if (parsed.length === 0) {
      setError('No valid messages found to import. Please paste messages or upload a valid file.')
      return
    }
    setImporting(true)
    setError('')
    try {
      const res = await api.importSmsBatch(parsed)
      setSuccessMsg(`Successfully imported and scanned ${res.imported_count} past messages: ${res.scam_count} scam(s), ${res.suspicious_count} suspicious, ${res.safe_count} safe.`)
      setImportInputText('')
      setShowImportPanel(false)
      await loadData(true)
    } catch (err) {
      setError(err.message || 'Batch import failed')
    } finally {
      setImporting(false)
    }
  }

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result
      if (typeof content === 'string') {
        setImportInputText(content)
      }
    }
    reader.readAsText(file)
  }

  const handleLoadSampleBatch = () => {
    const sample = `8558: Your Chase online banking OTP is 492011. Valid for 10 minutes.
+14159821102: USPS: Your package could not be delivered due to an incomplete address. Update at http://usps-parcel-track.xyz
3737: Your monthly mobile plan renewal of $45 is scheduled for tomorrow.
+19293021944: Wells Fargo URGENT: Your account has been suspended. Restore access immediately: http://wellsfargo-verify.xyz`
    setImportInputText(sample)
  }

  return (
    <div className="gmail-inbox-page fade-in" style={{ maxWidth: 1060 }}>
      {/* Header */}
      <div className="page-header" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div className="side-logo-icon" style={{ width: 34, height: 34 }}>
                <Smartphone size={18} strokeWidth={2.4} />
              </div>
              <h1 className="page-title" style={{ margin: 0 }}>SMS Inbox</h1>
            </div>
            <p className="page-subtitle" style={{ marginTop: 4 }}>
              Real-time mobile message feed with AI-powered smishing, shortcode, and threat analysis
            </p>
          </div>

          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <button
              className="btn-secondary"
              onClick={() => {
                setShowImportPanel(prev => !prev)
                if (showSimPanel) setShowSimPanel(false)
              }}
              type="button"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 14px', fontSize: 13 }}
            >
              <Upload size={14} />
              <span>{showImportPanel ? 'Close Import' : 'Import Past SMS'}</span>
            </button>

            <button
              className="btn-secondary"
              onClick={() => {
                setShowSimPanel(prev => !prev)
                if (showImportPanel) setShowImportPanel(false)
              }}
              type="button"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 14px', fontSize: 13 }}
            >
              <Sparkles size={14} />
              <span>{showSimPanel ? 'Hide Simulator' : 'Test Simulator'}</span>
            </button>

            <button
              className="btn-secondary"
              onClick={() => loadData(true)}
              disabled={refreshing}
              type="button"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 14px', fontSize: 13 }}
            >
              <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
              <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="card" style={{ padding: '12px 16px', marginBottom: 16, borderColor: 'var(--accent-red)', color: 'var(--accent-red)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div className="card" style={{ padding: '10px 16px', marginBottom: 16, borderColor: 'var(--accent-green)', color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <CheckCircle2 size={16} />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Import Past SMS Panel */}
      {showImportPanel && (
        <div className="card" style={{ padding: '18px 20px', marginBottom: 20, borderColor: 'var(--accent-primary)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexWrap: 'wrap', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Upload size={16} color="var(--accent-primary)" />
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>Import Past SMS Messages</h3>
            </div>
            <button
              className="btn-secondary"
              onClick={handleLoadSampleBatch}
              type="button"
              style={{ fontSize: 12, padding: '4px 10px', display: 'inline-flex', alignItems: 'center', gap: 5 }}
            >
              <FileText size={13} />
              <span>Load Sample History</span>
            </button>
          </div>

          <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 14 }}>
            Upload an export file from your phone (Android SMS Backup XML, CSV, or JSON) or paste your message history directly. Scam Shield will scan every message for phishing, urgent pressure, and smishing scams.
          </p>

          <div style={{ marginBottom: 12 }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, fontWeight: 500, color: 'var(--text-primary)', cursor: 'pointer', padding: '6px 12px', border: '1px dashed var(--border)', borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)' }}>
              <Upload size={13} />
              <span>Upload .json, .csv, or .xml file</span>
              <input
                type="file"
                accept=".json,.csv,.xml,.txt"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
            </label>
          </div>

          <textarea
            rows={5}
            placeholder={`Paste messages in any format:
8558: Your Chase verification code is 492011
+14159821102: USPS: Update incomplete address at http://usps-update.xyz
+19293021944: Wells Fargo account locked. Verify now: http://wellsfargo-verify.xyz`}
            value={importInputText}
            onChange={e => setImportInputText(e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              fontSize: 12.5,
              fontFamily: 'monospace',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border)',
              background: 'var(--bg-primary)',
              color: 'var(--text-primary)',
              lineHeight: 1.5,
              marginBottom: 12,
              resize: 'vertical',
            }}
          />

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {importInputText.trim()
                ? `Detected ~${parseMessagesFromInput(importInputText).length} message(s) ready to scan`
                : 'Supports Android XML backups, JSON lists, or colon-separated text'}
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <button
                className="btn-secondary"
                onClick={() => {
                  setImportInputText('')
                  setShowImportPanel(false)
                }}
                type="button"
                style={{ fontSize: 12.5, padding: '7px 14px' }}
              >
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={handleParseAndImport}
                disabled={importing || !importInputText.trim()}
                type="button"
                style={{ fontSize: 12.5, padding: '7px 16px', display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                {importing ? (
                  <>
                    <RefreshCw size={13} className="animate-spin" />
                    <span>Scanning & Importing...</span>
                  </>
                ) : (
                  <>
                    <Upload size={13} />
                    <span>Scan & Import All</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Phone Connection Panel */}
      <div className="card" style={{ padding: '18px 20px', marginBottom: 20 }}>
        {status?.connected ? (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: 'var(--accent-green)', display: 'inline-block' }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>
                    Connected Phone: <span style={{ fontFamily: 'monospace' }}>{status.phone_number}</span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    Total scanned messages: {status.total_messages} • Scams blocked: {status.scam_count}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn-secondary"
                  onClick={copyCurlWebhook}
                  type="button"
                  style={{ fontSize: 12, padding: '5px 12px', display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  {copiedCurl ? <Check size={13} color="var(--accent-green)" /> : <Copy size={13} />}
                  <span>{copiedCurl ? 'Webhook Copied!' : 'Copy Webhook cURL'}</span>
                </button>
                <button
                  className="btn-secondary"
                  onClick={copySyncToken}
                  type="button"
                  style={{ fontSize: 12, padding: '5px 12px', display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  {copiedToken ? <Check size={13} color="var(--accent-green)" /> : <Copy size={13} />}
                  <span>{copiedToken ? 'Token Copied!' : 'Copy Sync Token'}</span>
                </button>
                <button
                  className="btn-danger"
                  onClick={handleDisconnect}
                  type="button"
                  style={{ fontSize: 12, padding: '5px 12px' }}
                >
                  Disconnect
                </button>
              </div>
            </div>

            <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border)', fontSize: 12, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Info size={14} color="var(--accent-primary)" />
              <span>
                To auto-forward real SMS from Android, use any SMS webhook forwarder with endpoint:
                <code style={{ marginLeft: 6, padding: '2px 6px', background: 'var(--bg-secondary)', borderRadius: 4 }}>
                  POST /api/sms/receive?token={status.sync_token?.slice(0, 16)}...
                </code>
              </span>
            </div>
          </div>
        ) : (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Smartphone size={18} color="var(--accent-primary)" />
              <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600 }}>Connect Your Phone Number</h3>
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 14 }}>
              Register your phone number to generate a personal Webhook Token for real-time mobile SMS scanning.
            </p>

            <form onSubmit={handleConnect} style={{ display: 'flex', gap: 10, maxWidth: 500 }}>
              <input
                type="text"
                placeholder="+14155552671 or your mobile number"
                value={phoneInput}
                onChange={e => setPhoneInput(e.target.value)}
                required
                style={{
                  flex: 1,
                  padding: '9px 12px',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  fontSize: 13,
                }}
              />
              <button
                type="submit"
                disabled={connecting}
                className="btn-primary"
                style={{ padding: '9px 16px', fontSize: 13, whiteSpace: 'nowrap' }}
              >
                {connecting ? 'Connecting...' : 'Connect Number'}
              </button>
            </form>
          </div>
        )}
      </div>

      {/* Simulator Drawer (Collapsible) */}
      {showSimPanel && (
        <div className="card" style={{ padding: '18px 20px', marginBottom: 20, borderColor: 'var(--accent-primary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <Sparkles size={16} color="var(--accent-primary)" />
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>Test Ingest & Smishing Simulator</h3>
          </div>
          <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 14 }}>
            Click any realistic preset below to simulate an incoming SMS, or write a custom message to test the ML detection engine.
          </p>

          {/* Presets Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10, marginBottom: 18 }}>
            {PRESETS.map(p => (
              <button
                key={p.id}
                onClick={() => handleSimulatePreset(p.id)}
                disabled={simulating}
                type="button"
                className="card"
                style={{
                  textAlign: 'left',
                  padding: '10px 12px',
                  cursor: 'pointer',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                  transition: 'transform 0.15s, border-color 0.15s',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{p.title}</span>
                  <span className={`badge badge-${p.type}`} style={{ fontSize: '0.7em', padding: '2px 6px' }}>
                    {p.type.toUpperCase()}
                  </span>
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.35 }}>{p.desc}</div>
              </button>
            ))}
          </div>

          {/* Custom SMS Form */}
          <form onSubmit={handleCustomSimulate} style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}>
            <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 8, color: 'var(--text-primary)' }}>
              Or test a custom SMS:
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Sender ID (e.g. 8558, BANKALERT, +14159821102)"
                value={customSender}
                onChange={e => setCustomSender(e.target.value)}
                required
                style={{
                  width: 240,
                  padding: '8px 10px',
                  fontSize: 12.5,
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                }}
              />
              <input
                type="text"
                placeholder="Message body content..."
                value={customMessage}
                onChange={e => setCustomMessage(e.target.value)}
                required
                style={{
                  flex: 1,
                  minWidth: 260,
                  padding: '8px 10px',
                  fontSize: 12.5,
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                }}
              />
              <button
                type="submit"
                disabled={simulating}
                className="btn-primary"
                style={{ padding: '8px 16px', fontSize: 12.5, display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <Send size={13} />
                <span>{simulating ? 'Analyzing...' : 'Simulate'}</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Search and Filters Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 6 }}>
          {[
            { id: 'all', label: 'All' },
            { id: 'scam', label: `Scam (${status?.scam_count ?? 0})` },
            { id: 'suspicious', label: `Suspicious (${status?.suspicious_count ?? 0})` },
            { id: 'safe', label: `Safe (${status?.safe_count ?? 0})` },
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setActiveFilter(f.id)}
              className={`btn-secondary ${activeFilter === f.id ? 'active' : ''}`}
              type="button"
              style={{
                fontSize: 12,
                padding: '6px 14px',
                whiteSpace: 'nowrap',
                borderColor: activeFilter === f.id ? 'var(--accent-primary)' : 'var(--border)',
                background: activeFilter === f.id ? 'var(--accent-primary)' : 'transparent',
                color: activeFilter === f.id ? '#ffffff' : 'var(--text-secondary)',
              }}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div style={{ position: 'relative', minWidth: 240 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search sender or keywords..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 10px 6px 32px',
              fontSize: 12.5,
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
            }}
          />
        </div>
      </div>

      {/* Message List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
          <span className="loader" style={{ display: 'inline-block', marginBottom: 10 }} />
          <div>Loading SMS messages...</div>
        </div>
      ) : messages.length === 0 ? (
        <div className="card" style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <Smartphone size={32} strokeWidth={1.5} style={{ opacity: 0.5, marginBottom: 8 }} />
          <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
            No SMS messages found
          </div>
          <div style={{ fontSize: 13, maxWidth: 440, margin: '0 auto 16px' }}>
            {searchQuery || activeFilter !== 'all'
              ? 'Try adjusting your search query or filter.'
              : 'Your inbox is ready. Click "Test Simulator" above to inject test messages, or use your webhook token to stream real SMS messages.'}
          </div>
          {!searchQuery && activeFilter === 'all' && (
            <button
              className="btn-primary"
              onClick={() => handleSimulatePreset('package_delivery_scam')}
              type="button"
              style={{ fontSize: 13, padding: '8px 16px' }}
            >
              Simulate First Test SMS
            </button>
          )}
        </div>
      ) : (
        <div className="gmail-list">
          {messages.map(m => {
            const isExpanded = expandedId === m.id
            return (
              <article
                key={m.id}
                className="card gmail-email-card"
                style={{
                  cursor: 'pointer',
                  borderLeft: `4px solid ${
                    m.scam_level === 'scam'
                      ? 'var(--accent-red)'
                      : m.scam_level === 'suspicious'
                      ? 'var(--accent-yellow)'
                      : 'var(--accent-green)'
                  }`,
                  marginBottom: 10,
                }}
                onClick={() => setExpandedId(isExpanded ? null : m.id)}
              >
                <div className="gmail-email-header">
                  <div className="gmail-email-main">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <span className="gmail-email-sender" style={{ fontFamily: 'monospace', fontSize: 13.5 }}>
                        {m.sender_id}
                      </span>
                      {/^\d{4,6}$/.test(m.sender_id) && (
                        <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa' }}>
                          Shortcode
                        </span>
                      )}
                      <ScamBadge level={m.scam_level} confidence={m.confidence} />
                    </div>

                    <div className="gmail-email-subject" style={{ color: 'var(--text-primary)', fontSize: 13.5 }}>
                      {m.message}
                    </div>

                    <div className="gmail-email-meta">
                      <span>{new Date(m.timestamp).toLocaleString()}</span>
                      {m.reasons && m.reasons.length > 0 && (
                        <span>• {m.reasons.length} indicator{m.reasons.length > 1 ? 's' : ''} detected</span>
                      )}
                    </div>
                  </div>

                  <div className="gmail-email-actions" onClick={e => e.stopPropagation()}>
                    <button
                      className="mail-action-button"
                      onClick={() => setExpandedId(isExpanded ? null : m.id)}
                      type="button"
                      title={isExpanded ? 'Collapse' : 'Inspect'}
                    >
                      {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      <span>{isExpanded ? 'Less' : 'Inspect'}</span>
                    </button>
                    <button
                      className="mail-action-button danger"
                      onClick={e => handleDeleteMessage(m.id, e)}
                      type="button"
                      title="Delete SMS"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>

                {/* Expanded Inspection View */}
                {isExpanded && (
                  <div className="gmail-email-body" style={{ marginTop: 14 }}>
                    <div style={{ marginBottom: 12 }}>
                      <strong style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>
                        FULL MESSAGE CONTENT:
                      </strong>
                      <div style={{ fontFamily: 'monospace', fontSize: 13, background: 'var(--bg-primary)', padding: '10px 12px', borderRadius: 'var(--radius-sm)' }}>
                        {m.message}
                      </div>
                    </div>

                    {m.explanation && (
                      <div className="gmail-email-explanation" style={{ marginBottom: 12 }}>
                        <strong style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: 'var(--text-primary)', marginBottom: 4 }}>
                          <Info size={13} color="var(--accent-primary)" />
                          <span>AI Scam Analysis:</span>
                        </strong>
                        <div style={{ fontSize: 12.5, lineHeight: 1.5 }}>{m.explanation}</div>
                      </div>
                    )}

                    {m.reasons && m.reasons.length > 0 && (
                      <div>
                        <strong style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 6 }}>
                          KEY RISK FACTORS:
                        </strong>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          {m.reasons.map((r, i) => (
                            <span
                              key={i}
                              style={{
                                fontSize: 11.5,
                                padding: '3px 8px',
                                borderRadius: 4,
                                background: m.scam_level === 'scam' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                                color: m.scam_level === 'scam' ? '#f87171' : '#fbbf24',
                                border: '1px solid currentColor',
                              }}
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </article>
            )
          })}
        </div>
      )}
    </div>
  )
}

