import { useState, useEffect } from 'react'
import { api } from '../../api/client'
import { formatLocalDateTime } from '../../utils/date'
import {
  Mail,
  MessageSquare,
  Link2,
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
      <IconComp size={10.5} strokeWidth={2.4} />
      {b.label}
    </span>
  )
}

const TypeIcon = ({ type }) => {
  if (type === 'email') return <Mail size={15} />
  if (type === 'sms') return <MessageSquare size={15} />
  if (type === 'url') return <Link2 size={15} />
  return <Search size={15} />
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
    return formatLocalDateTime(ts, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    })
  }

  return (
    <div className="fade-in">
      <div className="page-header stagger stagger-1" style={{ display: 'flex', justifyContent: 'space-between',
                    alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <h1 className="page-title">Alerts & Logs</h1>
          <p className="page-subtitle">
            {detections.length} recorded scan results and threat reviews
          </p>
        </div>
        <button onClick={load} className="btn-secondary"
          type="button"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, padding: '7px 12px' }}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="stagger stagger-2" style={{ display: 'flex', gap: 6, marginBottom: 18, flexWrap: 'wrap' }}>
        {['all', 'scam', 'suspicious', 'safe', 'email', 'sms', 'url'].map(f => (
          <button key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: '5px 12px', borderRadius: 20, cursor: 'pointer',
              fontSize: 11.5, fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
              letterSpacing: '0.03em', transition: 'all 0.12s ease',
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
        <div className="stagger stagger-3" style={{ display: 'flex', alignItems: 'center', gap: 10,
                      color: 'var(--text-secondary)', padding: 36, justifyContent: 'center', fontSize: 13 }}>
          <span className="loader"></span> Loading detection history...
        </div>
      ) : !filtered.length ? (
        <div className="card stagger stagger-3" style={{ padding: 44, textAlign: 'center' }}>
          <div style={{ color: 'var(--text-muted)', marginBottom: 10 }}>
            <Search size={32} style={{ margin: '0 auto', opacity: 0.4 }} />
          </div>
          <div style={{ color: 'var(--text-primary)', fontSize: 14.5, fontWeight: 600 }}>No detections found</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12.5, marginTop: 4 }}>
            Run a scan to see logged findings here
          </div>
        </div>
      ) : (
        <div className="stagger stagger-3" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {filtered.map(d => (
            <div key={d.id} className="card"
              style={{ overflow: 'hidden' }}>
              {/* Row */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 14,
                padding: '12px 16px', cursor: 'pointer'
              }}
                onClick={() => setExpanded(expanded === d.id ? null : d.id)}>
                {/* Type icon */}
                <div style={{
                  width: 34, height: 34, borderRadius: 'var(--radius-sm)', flexShrink: 0,
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  color: 'var(--accent-primary)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <TypeIcon type={d.detection_type} />
                </div>

                {/* Info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8,
                                marginBottom: 2 }}>
                    <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text-primary)',
                                   fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>
                      {d.detection_type}
                    </span>
                    {d.source === 'gmail' && (
                      <span style={{ fontSize: 9.5, color: 'var(--accent-primary)', fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
                                     background: 'rgba(59, 130, 246, 0.1)', padding: '1px 5px', borderRadius: 4 }}>
                        Gmail
                      </span>
                    )}
                    <Badge level={d.scam_level} />
                  </div>
                  {(d.input_data?.subject || d.input_data?.sender) && (
                    <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 2,
                                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {[d.input_data?.sender, d.input_data?.subject].filter(Boolean).join(' • ')}
                    </div>
                  )}
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)',
                                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {d.reasons?.[0] || 'No specific reasons provided'}
                  </div>
                </div>

                {/* Confidence + Date */}
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ fontFamily: 'JetBrains Mono', fontSize: 12.5, fontWeight: 700,
                                color: d.scam_level === 'scam' ? 'var(--accent-red)'
                                     : d.scam_level === 'suspicious' ? 'var(--accent-yellow)' : 'var(--accent-green)' }}>
                    {d.confidence}%
                  </div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                    {formatDate(d.timestamp)}
                  </div>
                </div>

                <div style={{ color: 'var(--text-muted)', paddingLeft: 6 }}>
                  {expanded === d.id ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                </div>
              </div>

              {/* Expanded */}
              {expanded === d.id && (
                <div style={{ padding: '0 16px 14px',
                              borderTop: '1px solid var(--border-subtle)' }}>
                  <div style={{ paddingTop: 12 }}>
                    <div style={{ fontSize: 11.5, color: 'var(--text-primary)', fontWeight: 600,
                                  marginBottom: 6 }}>Detection Factors:</div>
                    {d.reasons?.map((r, i) => (
                      <div key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', padding: '3px 0',
                                            display: 'flex', alignItems: 'center', gap: 6 }}>
                        <ChevronRight size={12} color="var(--accent-primary)" />
                        <span>{r}</span>
                      </div>
                    ))}
                    {d.explanation && (
                      <div style={{ marginTop: 10, padding: 10, borderRadius: 'var(--radius-sm)',
                                    background: 'var(--bg-secondary)',
                                    border: '1px solid var(--border)',
                                    fontSize: 12, color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--accent-primary)', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <Info size={11} />
                          <span>Analysis:</span>
                        </span>
                        <div style={{ marginTop: 3, lineHeight: 1.55 }}>{d.explanation}</div>
                      </div>
                    )}
                    <button onClick={() => handleDelete(d.id)}
                      className="btn-danger"
                      type="button"
                      style={{ marginTop: 10, display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, padding: '5px 10px' }}>
                      <Trash2 size={12} />
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
