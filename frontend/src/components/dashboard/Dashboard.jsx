import { useState, useEffect } from 'react'
import { api } from '../../api/client'
import GmailConnect from './GmailConnect'
import {
  ScanSearch,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Mail,
  MessageSquare,
  Link2,
  ArrowRight,
  ShieldX,
  Activity,
  Calendar
} from 'lucide-react'

const StatCard = ({ icon: Icon, label, value, color, bgLight }) => (
  <div className="glass stagger" style={{ padding: '20px 22px' }}>
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
      <span style={{ fontSize: 13, color: 'var(--text-secondary)', fontWeight: 500 }}>{label}</span>
      <div style={{
        width: 32, height: 32, borderRadius: 8,
        background: bgLight || 'rgba(56, 189, 248, 0.1)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: color
      }}>
        <Icon size={16} strokeWidth={2.2} />
      </div>
    </div>
    <div style={{ fontSize: 28, fontWeight: 700, fontFamily: 'Plus Jakarta Sans, sans-serif', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
      {value}
    </div>
  </div>
)

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
      <IconComp size={11} strokeWidth={2.5} />
      {b.label}
    </span>
  )
}

const ActivityChart = ({ trend }) => {
  const [hoverIndex, setHoverIndex] = useState(null)

  const data = Array.isArray(trend) && trend.length ? trend : [
    { date: 'Day 1', count: 0 },
    { date: 'Day 2', count: 0 },
    { date: 'Day 3', count: 0 },
    { date: 'Day 4', count: 0 },
    { date: 'Day 5', count: 0 },
    { date: 'Day 6', count: 0 },
    { date: 'Day 7', count: 0 },
  ]

  const counts = data.map(d => Number(d.count) || 0)
  const maxVal = Math.max(...counts, 4)
  const total7Days = counts.reduce((a, b) => a + b, 0)

  const width = 640
  const height = 150
  const padX = 40
  const padTop = 26
  const padBottom = 28
  const plotWidth = width - padX * 2
  const plotHeight = height - padTop - padBottom
  const baselineY = height - padBottom

  const stepX = data.length > 1 ? plotWidth / (data.length - 1) : plotWidth
  const points = data.map((d, i) => {
    const x = padX + i * stepX
    const y = baselineY - (counts[i] / maxVal) * plotHeight
    return { x, y, date: d.date, count: counts[i] }
  })

  const lineD = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
  const areaD = `${lineD} L ${points[points.length - 1].x.toFixed(1)} ${baselineY} L ${points[0].x.toFixed(1)} ${baselineY} Z`

  return (
    <div className="glass stagger stagger-3" style={{ padding: '20px 24px', marginBottom: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12, marginBottom: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={16} color="var(--accent-cyan)" />
            <h3 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>
              7-Day Scan Activity
            </h3>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 2 }}>
            Daily scan volume across all detection channels
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6,
                      background: 'rgba(56, 189, 248, 0.08)',
                      border: '1px solid rgba(56, 189, 248, 0.2)',
                      padding: '4px 12px', borderRadius: 20 }}>
          <Calendar size={13} color="var(--accent-cyan)" />
          <span style={{ fontSize: 12, color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
            {total7Days} scans this week
          </span>
        </div>
      </div>

      <div style={{ width: '100%', overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          style={{ width: '100%', minWidth: 420, height: 'auto', display: 'block' }}
        >
          <defs>
            <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity="0.28" />
              <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Reference Gridlines */}
          <line
            x1={padX}
            y1={padTop}
            x2={width - padX}
            y2={padTop}
            stroke="var(--border)"
            strokeDasharray="3 3"
          />
          <line
            x1={padX}
            y1={padTop + plotHeight / 2}
            x2={width - padX}
            y2={padTop + plotHeight / 2}
            stroke="var(--border)"
            strokeDasharray="3 3"
          />
          <line
            x1={padX}
            y1={baselineY}
            x2={width - padX}
            y2={baselineY}
            stroke="var(--border)"
          />

          {/* Area Fill */}
          <path d={areaD} fill="url(#trendGrad)" />

          {/* Trend Line */}
          <path
            d={lineD}
            fill="none"
            stroke="var(--accent-cyan)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Data Points and Labels */}
          {points.map((p, i) => {
            const isHovered = hoverIndex === i
            return (
              <g
                key={i}
                onMouseEnter={() => setHoverIndex(i)}
                onMouseLeave={() => setHoverIndex(null)}
                style={{ cursor: 'pointer' }}
              >
                {/* Vertical hover guide */}
                {isHovered && (
                  <line
                    x1={p.x}
                    y1={padTop}
                    x2={p.x}
                    y2={baselineY}
                    stroke="var(--accent-cyan)"
                    strokeOpacity="0.4"
                    strokeWidth="1"
                    strokeDasharray="2 2"
                  />
                )}

                {/* Point circle */}
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={isHovered ? 5.5 : 3.5}
                  fill="var(--bg-card)"
                  stroke="var(--accent-cyan)"
                  strokeWidth={isHovered ? 2.5 : 2}
                  style={{ transition: 'all 0.15s ease' }}
                />

                {/* Value tooltip above point */}
                {(isHovered || p.count > 0) && (
                  <text
                    x={p.x}
                    y={p.y - 8}
                    textAnchor="middle"
                    fill={isHovered ? 'var(--text-primary)' : 'var(--text-secondary)'}
                    fontSize="10"
                    fontFamily="JetBrains Mono, monospace"
                    fontWeight="700"
                  >
                    {p.count}
                  </text>
                )}

                {/* Date label at bottom */}
                <text
                  x={p.x}
                  y={height - 8}
                  textAnchor="middle"
                  fill={isHovered ? 'var(--text-primary)' : 'var(--text-muted)'}
                  fontSize="11"
                  fontFamily="Inter, sans-serif"
                  fontWeight={isHovered ? '600' : '400'}
                >
                  {p.date}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
    </div>
  )
}

export default function Dashboard({ setPage }) {
  const [stats,   setStats]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [gmail, setGmail]     = useState(null)
  const [gmailBusy, setGmailBusy] = useState(false)
  const [gmailError, setGmailError] = useState('')

  useEffect(() => {
    let mounted = true

    const loadDashboardState = async () => {
      const [statsResult, gmailResult] = await Promise.allSettled([
        api.getStats(),
        api.getGmailStatus()
      ])

      if (!mounted) return

      if (statsResult.status === 'fulfilled') setStats(statsResult.value)
      if (gmailResult.status === 'fulfilled') setGmail(gmailResult.value)
      setLoading(false)
    }

    loadDashboardState().catch(console.error)

    const intervalId = window.setInterval(() => {
      loadDashboardState().catch(console.error)
    }, 30000)

    return () => {
      mounted = false
      window.clearInterval(intervalId)
    }
  }, [])

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const gmailState = params.get('gmail')
    if (gmailState === 'error') {
      setGmailError(params.get('message') || 'Gmail connection failed. Please try again.')
      window.history.replaceState({}, document.title, window.location.pathname)
    } else if (gmailState === 'connected') {
      setGmailError('')
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }, [])

  const refreshGmail = async () => {
    setGmailBusy(true)
    setGmailError('')
    try {
      const [statsData, gmailData] = await Promise.all([
        api.getStats(),
        api.getGmailStatus(),
      ])
      setStats(statsData)
      setGmail(gmailData)
    } catch (err) {
      setGmailError(err.message)
    } finally {
      setGmailBusy(false)
    }
  }

  const connectGmail = async () => {
    setGmailBusy(true)
    setGmailError('')
    try {
      const { auth_url } = await api.getGmailConnectUrl()
      window.location.href = auth_url
    } catch (err) {
      setGmailError(err.message)
    } finally {
      setGmailBusy(false)
    }
  }

  const connectGmailImap = async (payload) => {
    setGmailBusy(true)
    setGmailError('')
    try {
      await api.connectGmailImap(payload)
      await refreshGmail()
      return true
    } catch (err) {
      setGmailError(err.message)
      return false
    } finally {
      setGmailBusy(false)
    }
  }

  const syncGmail = async () => {
    setGmailBusy(true)
    setGmailError('')
    try {
      await api.syncGmail()
      await refreshGmail()
      api.getStats().then(setStats).catch(console.error)
    } catch (err) {
      setGmailError(err.message)
    } finally {
      setGmailBusy(false)
    }
  }

  const disconnectGmail = async () => {
    setGmailBusy(true)
    setGmailError('')
    try {
      await api.disconnectGmail()
      await refreshGmail()
    } catch (err) {
      setGmailError(err.message)
    } finally {
      setGmailBusy(false)
    }
  }

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                  height: 380, gap: 12, color: 'var(--text-secondary)' }}>
      <span className="loader"></span> Loading dashboard metrics...
    </div>
  )

  const score = stats?.security_score ?? 100

  return (
    <div className="fade-in">
      <div className="page-header stagger stagger-1">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-subtitle">
          Real-time threat detection overview and status
        </p>
      </div>

      <div className="glass stagger stagger-2" style={{
        padding: '22px 24px', marginBottom: 24,
        display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap'
      }}>
        <div style={{
          width: 72, height: 72, borderRadius: '50%',
          background: `conic-gradient(${score >= 80 ? 'var(--accent-green)' : score >= 50 ? 'var(--accent-yellow)' : 'var(--accent-red)'} ${score * 3.6}deg, var(--border) 0deg)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <div style={{
            width: 58, height: 58, borderRadius: '50%',
            background: 'var(--bg-card)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'JetBrains Mono', fontWeight: 700, fontSize: 16,
            color: score >= 80 ? 'var(--accent-green)' : score >= 50 ? 'var(--accent-yellow)' : 'var(--accent-red)'
          }}>{score}%</div>
        </div>

        <div style={{ flex: 1, minWidth: 240 }}>
          <div style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 18,
                        color: 'var(--text-primary)', marginBottom: 4 }}>
            Security Health Score
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
            {score >= 80 ? (
              <>
                <ShieldCheck size={16} color="var(--accent-green)" />
                <span>Low threat activity — recent scans clean</span>
              </>
            ) : score >= 50 ? (
              <>
                <AlertTriangle size={16} color="var(--accent-yellow)" />
                <span>Threats detected — review alerts</span>
              </>
            ) : (
              <>
                <ShieldAlert size={16} color="var(--accent-red)" />
                <span>Multiple threats detected — action recommended</span>
              </>
            )}
          </div>
        </div>

        <button className="btn-primary"
          onClick={() => setPage('detect')}
          type="button">
          <ScanSearch size={16} />
          <span>New Scan</span>
        </button>
      </div>

      <GmailConnect
        gmail={gmail}
        busy={gmailBusy}
        error={gmailError}
        onConnect={connectGmail}
        onConnectImap={connectGmailImap}
        onSync={syncGmail}
        onRefresh={refreshGmail}
        onDisconnect={disconnectGmail}
      />

      <div className="stats-grid">
        <StatCard
          icon={ScanSearch}
          label="Total Scans"
          value={stats?.total || 0}
          color="var(--accent-cyan)"
          bgLight="rgba(56, 189, 248, 0.12)"
        />
        <StatCard
          icon={ShieldAlert}
          label="Scams Detected"
          value={stats?.scam_count || 0}
          color="var(--accent-red)"
          bgLight="rgba(239, 68, 68, 0.12)"
        />
        <StatCard
          icon={AlertTriangle}
          label="Suspicious"
          value={stats?.suspicious_count || 0}
          color="var(--accent-yellow)"
          bgLight="rgba(245, 158, 11, 0.12)"
        />
        <StatCard
          icon={ShieldCheck}
          label="Safe"
          value={stats?.safe_count || 0}
          color="var(--accent-green)"
          bgLight="rgba(16, 185, 129, 0.12)"
        />
      </div>

      {/* 7-Day Activity Trend Chart */}
      <ActivityChart trend={stats?.trend} />

      <div className="split-grid">
        <div className="glass stagger stagger-3" style={{ padding: 22 }}>
          <h3 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 15,
                       marginBottom: 18, color: 'var(--text-primary)' }}>
            Scans by Type
          </h3>
          {[
            { label: 'Email', icon: Mail, count: stats?.by_type?.email || 0, color: 'var(--accent-cyan)' },
            { label: 'SMS', icon: MessageSquare, count: stats?.by_type?.sms || 0, color: '#a855f7' },
            { label: 'URLs', icon: Link2, count: stats?.by_type?.url || 0, color: 'var(--accent-green)' },
          ].map(t => {
            const IconComp = t.icon
            return (
              <div key={t.label} style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between',
                              marginBottom: 6, fontSize: 13 }}>
                  <span style={{ color: 'var(--text-secondary)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <IconComp size={14} color={t.color} />
                    {t.label}
                  </span>
                  <span style={{ color: 'var(--text-primary)', fontFamily: 'JetBrains Mono',
                                 fontWeight: 600 }}>{t.count}</span>
                </div>
                <div style={{ height: 6, background: 'var(--bg-secondary)',
                              borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', borderRadius: 3, background: t.color,
                    width: `${stats?.total ? (t.count / stats.total) * 100 : 0}%`,
                    transition: 'width 0.6s ease'
                  }} />
                </div>
              </div>
            )
          })}
        </div>

        <div className="glass stagger stagger-4" style={{ padding: 22 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between',
                        alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 15,
                         color: 'var(--text-primary)' }}>Recent Detections</h3>
            <button onClick={() => setPage('alerts')}
              style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)',
                       cursor: 'pointer', fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <span>View all</span>
              <ArrowRight size={13} />
            </button>
          </div>
          {!stats?.recent?.length ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '36px 16px',
                          fontSize: 13 }}>
              No detections recorded yet.<br/>
              <button onClick={() => setPage('detect')}
                style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)',
                         cursor: 'pointer', marginTop: 8, fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <span>Run first scan</span>
                <ArrowRight size={13} />
              </button>
            </div>
          ) : stats.recent.map(d => (
            <div key={d.id} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '10px 0', borderBottom: '1px solid var(--border-subtle)'
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8,
                              marginBottom: 3 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono',
                                 textTransform: 'uppercase', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    {d.detection_type === 'email' ? <Mail size={12} /> : d.detection_type === 'sms' ? <MessageSquare size={12} /> : <Link2 size={12} />}
                    {d.detection_type}
                  </span>
                  {d.source === 'gmail' && (
                    <span style={{ fontSize: 10, color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
                                   background: 'rgba(56, 189, 248, 0.1)', padding: '1px 6px', borderRadius: 4 }}>
                      Gmail
                    </span>
                  )}
                </div>
                {d.input_data?.subject && (
                  <div style={{ fontSize: 13, color: 'var(--text-primary)', marginBottom: 2 }}>
                    {d.input_data.subject}
                  </div>
                )}
                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
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
