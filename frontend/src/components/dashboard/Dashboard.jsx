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
  Smartphone,
  Link2,
  ArrowRight,
  ShieldX,
  Activity,
  Calendar
} from 'lucide-react'

const StatCard = ({ icon, label, value, color, bgLight }) => {
  const Icon = icon
  return (
    <div className="card stagger" style={{ padding: '18px 20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <span style={{ fontSize: 13, color: 'var(--text-secondary)', fontWeight: 500 }}>{label}</span>
        <div style={{
          width: 32, height: 32, borderRadius: 'var(--radius-md)',
          background: bgLight || 'rgba(59, 130, 246, 0.1)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: color
        }}>
          {Icon ? <Icon size={16} strokeWidth={2.2} /> : null}
        </div>
      </div>
      <div style={{ fontSize: 26, fontWeight: 700, fontFamily: 'Plus Jakarta Sans, sans-serif', color: 'var(--text-primary)', letterSpacing: '-0.025em' }}>
        {value}
      </div>
    </div>
  )
}

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
  const height = 145
  const padX = 36
  const padTop = 24
  const padBottom = 26
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
    <div className="card stagger stagger-3" style={{ padding: '18px 22px', marginBottom: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12, marginBottom: 14 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <Activity size={15} color="var(--accent-primary)" />
            <h3 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 14.5, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              7-Day Scan Activity
            </h3>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: 12.5, marginTop: 2 }}>
            Daily scan volume across all detection channels
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6,
                      background: 'var(--bg-elevated)',
                      border: '1px solid var(--border)',
                      padding: '4px 10px', borderRadius: 20 }}>
          <Calendar size={12} color="var(--text-secondary)" />
          <span style={{ fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
            {total7Days} scans this week
          </span>
        </div>
      </div>

      <div style={{ width: '100%', overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          style={{ width: '100%', minWidth: 400, height: 'auto', display: 'block' }}
        >
          <defs>
            <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--accent-primary)" stopOpacity="0.22" />
              <stop offset="100%" stopColor="var(--accent-primary)" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Reference Gridlines */}
          <line
            x1={padX}
            y1={padTop}
            x2={width - padX}
            y2={padTop}
            stroke="var(--border)"
            strokeDasharray="2 3"
          />
          <line
            x1={padX}
            y1={padTop + plotHeight / 2}
            x2={width - padX}
            y2={padTop + plotHeight / 2}
            stroke="var(--border)"
            strokeDasharray="2 3"
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
            stroke="var(--accent-primary)"
            strokeWidth="2.2"
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
                    stroke="var(--accent-primary)"
                    strokeOpacity="0.3"
                    strokeWidth="1"
                    strokeDasharray="2 2"
                  />
                )}

                {/* Point circle */}
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={isHovered ? 5 : 3}
                  fill="var(--bg-card)"
                  stroke="var(--accent-primary)"
                  strokeWidth={isHovered ? 2.5 : 2}
                  style={{ transition: 'all 0.12s ease' }}
                />

                {/* Value tooltip above point */}
                {(isHovered || p.count > 0) && (
                  <text
                    x={p.x}
                    y={p.y - 7}
                    textAnchor="middle"
                    fill={isHovered ? 'var(--text-primary)' : 'var(--text-secondary)'}
                    fontSize="10"
                    fontFamily="JetBrains Mono, monospace"
                    fontWeight="600"
                  >
                    {p.count}
                  </text>
                )}

                {/* Date label at bottom */}
                <text
                  x={p.x}
                  y={height - 7}
                  textAnchor="middle"
                  fill={isHovered ? 'var(--text-primary)' : 'var(--text-muted)'}
                  fontSize="10.5"
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
                  height: 340, gap: 10, color: 'var(--text-secondary)', fontSize: 13 }}>
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

      <div className="card stagger stagger-2" style={{
        padding: '20px 22px', marginBottom: 20,
        display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap'
      }}>
        <div style={{
          width: 64, height: 64, borderRadius: '50%',
          background: `conic-gradient(${score >= 80 ? 'var(--accent-green)' : score >= 50 ? 'var(--accent-yellow)' : 'var(--accent-red)'} ${score * 3.6}deg, var(--border) 0deg)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <div style={{
            width: 52, height: 52, borderRadius: '50%',
            background: 'var(--bg-card)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'JetBrains Mono', fontWeight: 700, fontSize: 15,
            color: score >= 80 ? 'var(--accent-green)' : score >= 50 ? 'var(--accent-yellow)' : 'var(--accent-red)'
          }}>{score}%</div>
        </div>

        <div style={{ flex: 1, minWidth: 220 }}>
          <div style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 16.5,
                        color: 'var(--text-primary)', marginBottom: 3, letterSpacing: '-0.015em' }}>
            Security Health Score
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
            {score >= 80 ? (
              <>
                <ShieldCheck size={15} color="var(--accent-green)" />
                <span>Low threat activity — recent scans clean</span>
              </>
            ) : score >= 50 ? (
              <>
                <AlertTriangle size={15} color="var(--accent-yellow)" />
                <span>Threats detected — review alerts</span>
              </>
            ) : (
              <>
                <ShieldAlert size={15} color="var(--accent-red)" />
                <span>Multiple threats detected — review recommended</span>
              </>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn-secondary"
            onClick={() => setPage('sms')}
            type="button"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Smartphone size={15} />
            <span>SMS Inbox</span>
          </button>
          <button className="btn-primary"
            onClick={() => setPage('detect')}
            type="button">
            <ScanSearch size={15} />
            <span>New Scan</span>
          </button>
        </div>
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
          color="var(--accent-primary)"
          bgLight="rgba(59, 130, 246, 0.12)"
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
        <div className="card stagger stagger-3" style={{ padding: '18px 20px' }}>
          <h3 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 14.5,
                       marginBottom: 16, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            Scans by Type
          </h3>
          {[
            { label: 'Email', icon: Mail, count: stats?.by_type?.email || 0, color: 'var(--accent-primary)' },
            { label: 'SMS', icon: MessageSquare, count: stats?.by_type?.sms || 0, color: '#a855f7' },
            { label: 'URLs', icon: Link2, count: stats?.by_type?.url || 0, color: 'var(--accent-green)' },
          ].map(t => {
            const IconComp = t.icon
            return (
              <div key={t.label} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between',
                              marginBottom: 5, fontSize: 12.5 }}>
                  <span style={{ color: 'var(--text-secondary)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <IconComp size={13} color={t.color} />
                    {t.label}
                  </span>
                  <span style={{ color: 'var(--text-primary)', fontFamily: 'JetBrains Mono',
                                 fontWeight: 600 }}>{t.count}</span>
                </div>
                <div style={{ height: 5, background: 'var(--bg-secondary)',
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

        <div className="card stagger stagger-4" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between',
                        alignItems: 'center', marginBottom: 14 }}>
            <h3 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 14.5,
                         color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>Recent Detections</h3>
            <button onClick={() => setPage('alerts')}
              style={{ background: 'none', border: 'none', color: 'var(--accent-primary)',
                       cursor: 'pointer', fontSize: 12.5, fontWeight: 500, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <span>View all</span>
              <ArrowRight size={12} />
            </button>
          </div>
          {!stats?.recent?.length ? (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '32px 16px',
                          fontSize: 12.5 }}>
              No detections recorded yet.<br/>
              <button onClick={() => setPage('detect')}
                style={{ background: 'none', border: 'none', color: 'var(--accent-primary)',
                         cursor: 'pointer', marginTop: 8, fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <span>Run first scan</span>
                <ArrowRight size={12} />
              </button>
            </div>
          ) : stats.recent.map(d => (
            <div key={d.id} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '9px 0', borderBottom: '1px solid var(--border-subtle)'
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6,
                              marginBottom: 2 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono',
                                 textTransform: 'uppercase', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    {d.detection_type === 'email' ? <Mail size={11} /> : d.detection_type === 'sms' ? <MessageSquare size={11} /> : <Link2 size={11} />}
                    {d.detection_type}
                  </span>
                  {d.source === 'gmail' && (
                    <span style={{ fontSize: 9.5, color: 'var(--accent-primary)', fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
                                   background: 'rgba(59, 130, 246, 0.1)', padding: '1px 5px', borderRadius: 4 }}>
                      Gmail
                    </span>
                  )}
                </div>
                {d.input_data?.subject && (
                  <div style={{ fontSize: 12.5, color: 'var(--text-primary)', marginBottom: 2 }}>
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
