import { useState, useEffect } from 'react'
import { api } from '../../api/client'
import {
  Mail,
  MessageSquare,
  Link2,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  ShieldX,
  RefreshCw,
  Trash2,
  ChevronDown,
  ChevronUp,
  Search,
  ChevronRight,
  Info
} from 'lucide-react'

const Badge = ({ level }) => {
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

const TypeIcon = ({ type }) => {
  if (type === 'email') return <Mail size={16} />
  if (type === 'sms') return <MessageSquare size={16} />
  if (type === 'url') return <Link2 size={16} />
  return <Search size={16} />
}

export default function Alerts() {
  const [detections, setDetections] = useState([])
  const [loading,    setLoading]    = useState(true)
  const [filter,     setFilter]     = useState('all')
  const [expanded,   setExpanded]   = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const data = await api.getHistory(50)
      setDetections(data.results || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleDelete = async (id) => {
    await api.deleteDetection(id)
    setDetections(prev => prev.filter(d => d.id !== id))
  }

  const filtered = filter === 'all'
    ? detections
    : detections.filter(d => d.scam_level === filter || d.detection_type === filter)

  const formatDate = (ts) => {
    if (!ts) return ''
    return new Date(ts).toLocaleString('en-US', {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    })
  }

  return (
    <div className="fade-in">
      <div className="page-header stagger stagger-1" style={{ display: 'flex', justifyContent: 'space-between',
                    alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 className="page-title">Alerts & Logs</h1>
          <p className="page-subtitle">
            {detections.length} total detections recorded
          </p>
        </div>
        <button onClick={load} className="gmail-secondary-button"
          type="button"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="stagger stagger-2" style={{ display: 'flex', gap: 6, marginBottom: 20, flexWrap: 'wrap' }}>
        {['all', 'scam', 'suspicious', 'safe', 'email', 'sms', 'url'].map(f => (
          <button key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: '6px 14px', borderRadius: 20, cursor: 'pointer',
              fontSize: 12, fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
              letterSpacing: '0.04em', transition: 'all 0.15s ease',
              background: filter === f ? 'var(--bg-card)' : 'transparent',
              color: filter === f ? 'var(--text-primary)' : 'var(--text-muted)',
              border: filter === f ? '1px solid var(--border-hover)' : '1px solid var(--border)'
            }}>
            {f}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="stagger stagger-3" style={{ display: 'flex', alignItems: 'center', gap: 12,
                      color: 'var(--text-secondary)', padding: 40, justifyContent: 'center' }}>
          <span className="loader"></span> Loading detection history...
        </div>
      ) : !filtered.length ? (
        <div className="glass stagger stagger-3" style={{ padding: 48, textAlign: 'center' }}>
          <div style={{ color: 'var(--text-muted)', marginBottom: 12 }}>
            <Search size={36} style={{ margin: '0 auto', opacity: 0.5 }} />
          </div>
          <div style={{ color: 'var(--text-primary)', fontSize: 15, fontWeight: 600 }}>No detections found</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 4 }}>
            Run a scan to see logged findings here
          </div>
        </div>
      ) : (
        <div className="stagger stagger-3" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filtered.map(d => (
            <div key={d.id} className="glass"
              style={{ overflow: 'hidden' }}>
              {/* Row */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 14,
                padding: '14px 18px', cursor: 'pointer'
              }}
                onClick={() => setExpanded(expanded === d.id ? null : d.id)}>
                {/* Type icon */}
                <div style={{
                  width: 36, height: 36, borderRadius: 8, flexShrink: 0,
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  color: 'var(--accent-cyan)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <TypeIcon type={d.detection_type} />
                </div>

                {/* Info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8,
                                marginBottom: 3 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)',
                                   fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>
                      {d.detection_type}
                    </span>
                    {d.source === 'gmail' && (
                      <span style={{ fontSize: 10, color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
                                     background: 'rgba(56, 189, 248, 0.1)', padding: '1px 6px', borderRadius: 4 }}>
                        Gmail
                      </span>
                    )}
                    <Badge level={d.scam_level} />
                  </div>
                  {(d.input_data?.subject || d.input_data?.sender) && (
                    <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 2 }}>
                      {[d.input_data?.sender, d.input_data?.subject].filter(Boolean).join(' • ')}
                    </div>
                  )}
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {d.reasons?.[0] || 'No specific reasons provided'}
                  </div>
                </div>

                {/* Confidence + Date */}
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ fontFamily: 'JetBrains Mono', fontSize: 13, fontWeight: 700,
                                color: d.scam_level === 'scam' ? 'var(--accent-red)'
                                     : d.scam_level === 'suspicious' ? 'var(--accent-yellow)' : 'var(--accent-green)' }}>
                    {d.confidence}%
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                    {formatDate(d.timestamp)}
                  </div>
                </div>

                <div style={{ color: 'var(--text-muted)', paddingLeft: 8 }}>
                  {expanded === d.id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </div>
              </div>

              {/* Expanded */}
              {expanded === d.id && (
                <div style={{ padding: '0 18px 16px',
                              borderTop: '1px solid var(--border-subtle)' }}>
                  <div style={{ paddingTop: 14 }}>
                    <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 600,
                                  marginBottom: 8 }}>All Factors Detected:</div>
                    {d.reasons?.map((r, i) => (
                      <div key={i} style={{ fontSize: 13, color: 'var(--text-secondary)', padding: '4px 0',
                                            display: 'flex', alignItems: 'center', gap: 6 }}>
                        <ChevronRight size={13} color="var(--accent-cyan)" />
                        <span>{r}</span>
                      </div>
                    ))}
                    {d.explanation && (
                      <div style={{ marginTop: 12, padding: 12, borderRadius: 8,
                                    background: 'var(--bg-secondary)',
                                    border: '1px solid var(--border)',
                                    fontSize: 12, color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--accent-cyan)', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <Info size={12} />
                          <span>Analysis:</span>
                        </span>
                        <div style={{ marginTop: 4, lineHeight: 1.6 }}>{d.explanation}</div>
                      </div>
                    )}
                    <button onClick={() => handleDelete(d.id)}
                      className="gmail-danger-button"
                      type="button"
                      style={{ marginTop: 12, display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                      <Trash2 size={13} />
                      <span>Delete Record</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
