import { useEffect, useState } from 'react'
import { api } from '../../api/client'
import { formatLocalDateTime } from '../../utils/date'
import {
  ShieldCheck,
  AlertTriangle,
  ShieldX,
  Mail,
  Eye,
  EyeOff,
  CheckCircle2,
  RefreshCw,
  Info
} from 'lucide-react'

const ScamBadge = ({ level }) => {
  const map = {
    scam:       { cls: 'badge-scam',       label: 'SCAM',       Icon: ShieldX },
    suspicious: { cls: 'badge-suspicious', label: 'SUSPICIOUS', Icon: AlertTriangle },
    safe:       { cls: 'badge-safe',       label: 'SAFE',       Icon: ShieldCheck },
  }
  const b = map[level] || map.safe
  const IconComp = b.Icon
  return (
    <span className={`badge ${b.cls}`}>
      <IconComp size={11} strokeWidth={2.4} />
      {b.label}
    </span>
  )
}

const GmailInboxSkeleton = () => (
  <div className="gmail-inbox-page" aria-label="Loading Gmail inbox" aria-busy="true">
    <div className="page-header gmail-skeleton-header" style={{ marginBottom: 18 }}>
      <div className="gmail-skeleton gmail-skeleton-title" />
      <div className="gmail-skeleton gmail-skeleton-subtitle" />
    </div>
    <div className="gmail-list">
      {[1, 2, 3].map(item => (
        <article key={item} className="card gmail-email-card gmail-skeleton-card">
          <div className="gmail-email-header">
            <div className="gmail-email-main">
              <div className="gmail-skeleton gmail-skeleton-sender" />
              <div className="gmail-skeleton gmail-skeleton-subject" />
              <div className="gmail-skeleton gmail-skeleton-meta" />
            </div>
            <div className="gmail-skeleton-actions">
              <div className="gmail-skeleton gmail-skeleton-button" />
              <div className="gmail-skeleton gmail-skeleton-button" />
            </div>
          </div>
        </article>
      ))}
    </div>
  </div>
)

export default function GmailInbox({ setPage }) {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [actionState, setActionState] = useState({ id: null, type: '' })

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const status = await api.getGmailStatus()
      if (!status?.connected) {
        setEmails([])
        setError('Gmail is not connected. Connect your account from the dashboard to monitor emails.')
        return
      }

      const data = await api.getGmailInbox()
      setEmails(data || [])
    } catch (err) {
      setError(err.message || 'Failed to load Gmail inbox.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const scanEmail = async (id) => {
    setActionState({ id, type: 'scan' })
    try {
      const res = await api.scanGmailEmail(id)
      setEmails(prev => prev.map(e => e.id === id ? { ...e, scan: res } : e))
      setError('')
    } catch (err) {
      setError(err.message || String(err))
    } finally {
      setActionState({ id: null, type: '' })
    }
  }

  const toggleExpand = async (email) => {
    if (!email.full_body) {
      setActionState({ id: email.id, type: 'open' })
      try {
        const res = await api.fetchGmailEmail(email.id)
        setEmails(prev => prev.map(e => e.id === email.id ? { ...e, full_body: res.body, scan: res.scan } : e))
      } catch (err) {
        setError(err.message || String(err))
      } finally {
        setActionState({ id: null, type: '' })
      }
    } else {
      setEmails(prev => prev.map(e => e.id === email.id ? { ...e, full_body: null } : e))
    }
  }

  if (loading) return <GmailInboxSkeleton />
  if (error) return (
    <div className="gmail-inbox-page fade-in">
      <div className="page-header stagger stagger-1" style={{ marginBottom: 18 }}>
        <h1 className="page-title">Gmail Inbox</h1>
        <p className="page-subtitle">Inspect, verify, and review scanned messages in your inbox</p>
      </div>
      <div className="card" style={{ padding: 24, maxWidth: 640 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 16 }}>
          <AlertTriangle size={20} color="var(--accent-amber)" style={{ flexShrink: 0, marginTop: 2 }} />
          <div>
            <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>Account Not Connected</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: 13.5, lineHeight: 1.5, margin: 0 }}>
              {error}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
          {setPage && (
            <button
              type="button"
              className="btn-primary"
              onClick={() => setPage('dashboard')}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13, padding: '8px 16px' }}
            >
              <Mail size={14} />
              <span>Connect Account</span>
            </button>
          )}
          <button
            type="button"
            className="btn-secondary"
            onClick={load}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13, padding: '8px 14px' }}
          >
            <RefreshCw size={13} />
            <span>Retry</span>
          </button>
        </div>
      </div>
    </div>
  )

  return (
    <div className="gmail-inbox-page fade-in">
      <div className="page-header stagger stagger-1" style={{ marginBottom: 18 }}>
        <h1 className="page-title">Gmail Inbox</h1>
        <p className="page-subtitle">Inspect, verify, and review scanned messages in your inbox</p>
      </div>

      <div className="gmail-list">
        {emails.map(e => (
          <article key={e.id} className="card gmail-email-card stagger stagger-2">
            <div className="gmail-email-header">
              <div className="gmail-email-main">
                <div className="gmail-email-sender">{e.sender || 'Unknown Sender'}</div>
                <div className="gmail-email-subject">{e.subject}</div>
                <div className="gmail-email-meta">
                  <span>{e.date ? formatLocalDateTime(e.date) : 'Recently received'}</span>
                  {e.scan?.confidence != null && <span>• {e.scan.confidence}% confidence</span>}
                </div>
              </div>
              <div className="gmail-email-actions">
                <button
                  className={`mail-action-button ${actionState.id === e.id && actionState.type === 'open' ? 'is-busy' : ''}`}
                  onClick={() => toggleExpand(e)}
                  disabled={actionState.id === e.id && actionState.type === 'scan'}
                  type="button"
                >
                  {e.full_body ? <EyeOff size={13} /> : <Eye size={13} />}
                  <span>{actionState.id === e.id && actionState.type === 'open' ? 'Opening...' : e.full_body ? 'Collapse' : 'Inspect'}</span>
                </button>
                <button
                  className={`mail-action-button verify ${actionState.id === e.id && actionState.type === 'scan' ? 'is-busy' : ''}`}
                  onClick={() => scanEmail(e.id)}
                  type="button"
                >
                  <RefreshCw size={13} className={actionState.id === e.id && actionState.type === 'scan' ? 'animate-spin' : ''} />
                  <span>{actionState.id === e.id && actionState.type === 'scan' ? 'Verifying...' : e.scan ? 'Re-verify' : 'Verify'}</span>
                </button>
                {e.scan ? <ScamBadge level={e.scan.scam_level} /> : null}
              </div>
            </div>
            {e.full_body && (
              <div className="gmail-email-body">
                <div style={{ whiteSpace: 'pre-wrap' }}>{e.full_body}</div>
                {e.scan?.explanation && (
                  <div className="gmail-email-explanation">
                    <strong style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: 'var(--text-primary)', marginBottom: 4 }}>
                      <Info size={13} color="var(--accent-primary)" />
                      <span>Analysis:</span>
                    </strong>
                    <div>{e.scan.explanation}</div>
                  </div>
                )}
              </div>
            )}
          </article>
        ))}
      </div>
    </div>
  )
}
