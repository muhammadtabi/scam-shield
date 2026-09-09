import { useState, useEffect } from 'react'
import { api } from '../../api/client'

const Badge = ({ level }) => {
  const map = {
    scam:       { cls: 'badge-scam',       label: 'SCAM' },
    suspicious: { cls: 'badge-suspicious', label: 'SUSPICIOUS' },
    safe:       { cls: 'badge-safe',       label: 'SAFE' },
  }
  const b = map[level] || map.safe
  return <span className={`badge ${b.cls}`}>{b.label}</span>
}

const TypeIcon = ({ type }) => ({
  email: '📧', sms: '📱', url: '🔗'
}[type] || '🔍')

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
      <div className="stagger stagger-1" style={{ display: 'flex', justifyContent: 'space-between',
                    alignItems: 'flex-start', marginBottom: 32 }}>
        <div>
          <h1 style={{ fontFamily: 'Sora', fontWeight: 800, fontSize: 28,
                       color: '#e2e8f0', marginBottom: 6 }}>Alerts</h1>
          <p style={{ color: '#94a3b8', fontSize: 14 }}>
            {detections.length} total detections logged
          </p>
        </div>
        <button onClick={load}
          style={{ background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)',
                   borderRadius: 8, padding: '8px 16px', color: '#00d4ff',
                   cursor: 'pointer', fontSize: 13 }}>
          ↻ Refresh
        </button>
      </div>

      <div className="stagger stagger-2" style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
        {['all', 'scam', 'suspicious', 'safe', 'email', 'sms', 'url'].map(f => (
          <button key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: '6px 14px', borderRadius: 20, cursor: 'pointer',
              fontSize: 12, fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
              letterSpacing: '0.05em', transition: 'all 0.2s',
              background: filter === f ? 'rgba(0,212,255,0.2)' : 'rgba(13,31,60,0.8)',
              color: filter === f ? '#00d4ff' : '#94a3b8',
              border: filter === f ? '1px solid rgba(0,212,255,0.4)' : '1px solid transparent'
            }}>
            {f}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="stagger stagger-3" style={{ display: 'flex', alignItems: 'center', gap: 12,
                      color: '#94a3b8', padding: 40 }}>
          <span className="loader"></span> Loading alerts...
        </div>
      ) : !filtered.length ? (
        <div className="glass stagger stagger-3" style={{ padding: 60, textAlign: 'center' }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>🔍</div>
          <div style={{ color: '#94a3b8', fontSize: 15 }}>No detections found</div>
          <div style={{ color: '#475569', fontSize: 13, marginTop: 6 }}>
            Run a scan to see results here
          </div>
        </div>
      ) : (
        <div className="stagger stagger-3" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filtered.map(d => (
            <div key={d.id} className="glass"
              style={{ overflow: 'hidden', transition: 'all 0.2s' }}>
              {/* Row */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 14,
                padding: '14px 20px', cursor: 'pointer'
              }}
                onClick={() => setExpanded(expanded === d.id ? null : d.id)}>
                {/* Type icon */}
                <div style={{
                  width: 40, height: 40, borderRadius: 10, flexShrink: 0,
                  background: 'rgba(0,212,255,0.08)',
                  border: '1px solid rgba(0,212,255,0.15)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 18
                }}>
                  <TypeIcon type={d.detection_type} />
                </div>

                {/* Info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8,
                                marginBottom: 3 }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0',
                                   fontFamily: 'Sora', textTransform: 'uppercase' }}>
                      {d.detection_type}
                    </span>
                    <Badge level={d.scam_level} />
                  </div>
                  <div style={{ fontSize: 12, color: '#475569' }}>
                    {d.reasons?.[0] || 'No reason provided'}
                  </div>
                </div>

                {/* Confidence + Date */}
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ fontFamily: 'JetBrains Mono', fontSize: 14, fontWeight: 700,
                                color: d.scam_level === 'scam' ? '#ef4444'
                                     : d.scam_level === 'suspicious' ? '#f59e0b' : '#22c55e' }}>
                    {d.confidence}%
                  </div>
                  <div style={{ fontSize: 11, color: '#475569' }}>
                    {formatDate(d.timestamp)}
                  </div>
                </div>

                <span style={{ color: '#475569', fontSize: 12 }}>
                  {expanded === d.id ? '▲' : '▼'}
                </span>
              </div>

              {/* Expanded */}
              {expanded === d.id && (
                <div style={{ padding: '0 20px 16px',
                              borderTop: '1px solid rgba(0,212,255,0.06)' }}>
                  <div style={{ paddingTop: 14 }}>
                    <div style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600,
                                  marginBottom: 8 }}>All Reasons:</div>
                    {d.reasons?.map((r, i) => (
                      <div key={i} style={{ fontSize: 13, color: '#94a3b8', padding: '4px 0',
                                            display: 'flex', gap: 8 }}>
                        <span style={{ color: '#00d4ff' }}>›</span>{r}
                      </div>
                    ))}
                    {d.explanation && (
                      <div style={{ marginTop: 12, padding: 12, borderRadius: 8,
                                    background: 'rgba(0,212,255,0.05)',
                                    border: '1px solid rgba(0,212,255,0.1)',
                                    fontSize: 12, color: '#94a3b8' }}>
                        <span style={{ color: '#00d4ff', fontWeight: 600 }}>
                          🤖 AI: </span>{d.explanation}
                      </div>
                    )}
                    <button onClick={() => handleDelete(d.id)}
                      style={{ marginTop: 12, background: 'rgba(239,68,68,0.08)',
                               border: '1px solid rgba(239,68,68,0.2)',
                               borderRadius: 6, padding: '6px 14px',
                               color: '#ef4444', cursor: 'pointer', fontSize: 12 }}>
                      🗑 Delete
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
