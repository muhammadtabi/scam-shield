import { useState, useEffect } from 'react'
import { api } from '../../api/client'

const StatCard = ({ icon, label, value, color, sub }) => (
  <div className="glass stagger" style={{ padding: 24, position: 'relative', overflow: 'hidden' }}>
    <div style={{ position: 'absolute', top: -10, right: -10, fontSize: 60,
                  opacity: 0.06 }}>{icon}</div>
    <div style={{ fontSize: 28, marginBottom: 4 }}>{icon}</div>
    <div style={{ fontSize: 32, fontWeight: 800, fontFamily: 'Sora', color }}>
      {value}
    </div>
    <div style={{ fontSize: 13, color: '#94a3b8', marginTop: 2 }}>{label}</div>
    {sub && <div style={{ fontSize: 11, color: '#475569', marginTop: 4,
                          fontFamily: 'JetBrains Mono' }}>{sub}</div>}
  </div>
)

const ScamBadge = ({ level }) => {
  const map = {
    scam:       { cls: 'badge-scam',       label: 'SCAM' },
    suspicious: { cls: 'badge-suspicious', label: 'SUSPICIOUS' },
    safe:       { cls: 'badge-safe',       label: 'SAFE' },
  }
  const b = map[level] || map.safe
  return <span className={`badge ${b.cls}`}>{b.label}</span>
}

export default function Dashboard({ setPage }) {
  const [stats,   setStats]   = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getStats()
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                  height: 400, gap: 12, color: '#94a3b8' }}>
      <span className="loader"></span> Loading dashboard...
    </div>
  )

  const score = stats?.security_score || 100

  return (
    <div className="fade-in">
      <div className="page-header stagger stagger-1">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-subtitle">
          Real-time scam detection overview
        </p>
      </div>

      <div className="glass stagger stagger-2" style={{
        padding: 24, marginBottom: 24,
        background: score >= 80
          ? 'linear-gradient(135deg, rgba(34,197,94,0.08), rgba(13,31,60,0.8))'
          : score >= 50
          ? 'linear-gradient(135deg, rgba(245,158,11,0.08), rgba(13,31,60,0.8))'
          : 'linear-gradient(135deg, rgba(239,68,68,0.08), rgba(13,31,60,0.8))',
        display: 'flex', alignItems: 'center', gap: 24
      }}>
        <div style={{
          width: 80, height: 80, borderRadius: '50%',
          background: `conic-gradient(${score >= 80 ? '#22c55e' : score >= 50 ? '#f59e0b' : '#ef4444'} ${score * 3.6}deg, rgba(255,255,255,0.05) 0deg)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <div style={{
            width: 62, height: 62, borderRadius: '50%',
            background: 'var(--bg-card)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'Sora', fontWeight: 800, fontSize: 18,
            color: score >= 80 ? '#22c55e' : score >= 50 ? '#f59e0b' : '#ef4444'
          }}>{score}%</div>
        </div>
        <div>
          <div style={{ fontFamily: 'Sora', fontWeight: 700, fontSize: 20,
                        color: '#e2e8f0', marginBottom: 4 }}>
            Security Score
          </div>
          <div style={{ color: '#94a3b8', fontSize: 14 }}>
            {score >= 80 ? '✅ Your system is well protected'
             : score >= 50 ? '⚠️ Some threats detected — review alerts'
             : '🚨 Multiple threats detected — immediate action required'}
          </div>
          <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
            <button className="btn-cyber"
              onClick={() => setPage('detect')}
              style={{ padding: '8px 16px', fontSize: 13 }}>
              Run New Scan
            </button>
          </div>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stagger stagger-2">
          <StatCard icon="🔍" label="Total Scans"     value={stats?.total || 0}
                  color="#00d4ff" />
        </div>
        <div className="stagger stagger-3">
          <StatCard icon="🚨" label="Scams Detected"  value={stats?.scam_count || 0}
                  color="#ef4444" />
        </div>
        <div className="stagger stagger-4">
          <StatCard icon="⚠️" label="Suspicious"       value={stats?.suspicious_count || 0}
                  color="#f59e0b" />
        </div>
        <div className="stagger stagger-5">
          <StatCard icon="✅" label="Safe"             value={stats?.safe_count || 0}
                  color="#22c55e" />
        </div>
      </div>

      <div className="split-grid">
        <div className="glass stagger stagger-3" style={{ padding: 24 }}>
          <h3 style={{ fontFamily: 'Sora', fontWeight: 700, fontSize: 16,
                       marginBottom: 20, color: '#e2e8f0' }}>
            Scans by Type
          </h3>
          {[
            { label: 'Email', icon: '📧', count: stats?.by_type?.email || 0, color: '#0ea5e9' },
            { label: 'SMS / Calls', icon: '📱', count: stats?.by_type?.sms || 0, color: '#8b5cf6' },
            { label: 'URLs', icon: '🔗', count: stats?.by_type?.url || 0, color: '#22c55e' },
          ].map(t => (
            <div key={t.label} style={{ marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between',
                            marginBottom: 6, fontSize: 13 }}>
                <span style={{ color: '#94a3b8' }}>{t.icon} {t.label}</span>
                <span style={{ color: '#e2e8f0', fontFamily: 'JetBrains Mono',
                               fontWeight: 700 }}>{t.count}</span>
              </div>
              <div style={{ height: 6, background: 'rgba(255,255,255,0.05)',
                            borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 3, background: t.color,
                  width: `${stats?.total ? (t.count / stats.total) * 100 : 0}%`,
                  transition: 'width 1s ease'
                }} />
              </div>
            </div>
          ))}
        </div>

        <div className="glass stagger stagger-4" style={{ padding: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between',
                        alignItems: 'center', marginBottom: 20 }}>
            <h3 style={{ fontFamily: 'Sora', fontWeight: 700, fontSize: 16,
                         color: '#e2e8f0' }}>Recent Detections</h3>
            <button onClick={() => setPage('alerts')}
              style={{ background: 'none', border: 'none', color: '#00d4ff',
                       cursor: 'pointer', fontSize: 13 }}>
              View all →
            </button>
          </div>
          {!stats?.recent?.length ? (
            <div style={{ textAlign: 'center', color: '#475569', padding: 32,
                          fontSize: 14 }}>
              No detections yet.<br/>
              <button onClick={() => setPage('detect')}
                style={{ background: 'none', border: 'none', color: '#00d4ff',
                         cursor: 'pointer', marginTop: 8 }}>
                Run your first scan →
              </button>
            </div>
          ) : stats.recent.map(d => (
            <div key={d.id} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '10px 0', borderBottom: '1px solid rgba(0,212,255,0.06)'
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8,
                              marginBottom: 3 }}>
                  <span style={{ fontSize: 12, color: '#94a3b8', fontFamily: 'JetBrains Mono',
                                 textTransform: 'uppercase' }}>
                    {d.detection_type === 'email' ? '📧' : d.detection_type === 'sms' ? '📱' : '🔗'}
                    {' '}{d.detection_type}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: '#475569' }}>
                  {d.confidence}% confidence
                </div>
              </div>
              <ScamBadge level={d.scam_level} />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
