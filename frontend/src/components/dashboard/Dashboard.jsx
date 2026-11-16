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
  const [selectedDayIndex, setSelectedDayIndex] = useState(null)

  const data = Array.isArray(trend) && trend.length ? trend : []
  const total7Days = data.reduce((sum, d) => sum + (Number(d.count) || 0), 0)
  const totalScams7Days = data.reduce((sum, d) => sum + (Number(d.scams) || 0), 0)
  const totalSuspicious7Days = data.reduce((sum, d) => sum + (Number(d.suspicious) || 0), 0)
  const totalSafe7Days = data.reduce((sum, d) => sum + (Number(d.safe) || 0), 0)

  // Default to today (last index) or hovered/clicked index
  const activeIndex = selectedDayIndex !== null ? selectedDayIndex : (data.length > 0 ? data.length - 1 : 0)
  const activeDay = data[activeIndex] || null

  return (
    <div className="card stagger stagger-3" style={{ padding: '20px 24px', marginBottom: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12, marginBottom: 18 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={16} color="var(--accent-blue)" />
            <h3 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 15, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              7-Day Threat Activity Log
            </h3>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: 12.5, marginTop: 2 }}>
            Daily breakdown of verified scans and threat classifications by calendar date
          </p>
        </div>

        {/* Weekly Summary Badges */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          padding: '6px 14px',
          borderRadius: 'var(--radius-md)',
          fontSize: 12,
          flexWrap: 'wrap'
        }}>
          <span style={{ color: 'var(--text-secondary)', display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <Calendar size={13} />
            <strong style={{ color: 'var(--text-primary)', fontFamily: 'JetBrains Mono' }}>{total7Days}</strong> scans
          </span>
          <span style={{ width: 1, height: 12, background: 'var(--border)' }} />
          <span style={{ color: 'var(--accent-red)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-red)' }} />
            <strong>{totalScams7Days}</strong> scams
          </span>
          <span style={{ width: 1, height: 12, background: 'var(--border)' }} />
          <span style={{ color: 'var(--accent-yellow)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-yellow)' }} />
            <strong>{totalSuspicious7Days}</strong> suspicious
          </span>
          <span style={{ width: 1, height: 12, background: 'var(--border)' }} />
          <span style={{ color: 'var(--accent-green)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)' }} />
            <strong>{totalSafe7Days}</strong> safe
          </span>
        </div>
      </div>

      {/* 7-Day Date Columns Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))',
        gap: 10,
        marginBottom: 16
      }}>
        {data.map((day, idx) => {
          const count = Number(day.count) || 0
          const scams = Number(day.scams) || 0
          const suspicious = Number(day.suspicious) || 0
          const safe = Number(day.safe) || 0
          const isSelected = activeIndex === idx

          const scamPct = count > 0 ? (scams / count) * 100 : 0
          const suspPct = count > 0 ? (suspicious / count) * 100 : 0
          const safePct = count > 0 ? (safe / count) * 100 : 0

          return (
            <button
              key={idx}
              type="button"
              onMouseEnter={() => setSelectedDayIndex(idx)}
              onClick={() => setSelectedDayIndex(idx)}
              style={{
                background: isSelected ? 'var(--bg-elevated)' : 'var(--bg-secondary)',
                border: isSelected ? '1px solid var(--accent-blue)' : '1px solid var(--border)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease',
                position: 'relative',
                boxShadow: isSelected ? 'var(--shadow-sm)' : 'none'
              }}
            >
              {/* Day header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  color: isSelected ? 'var(--accent-blue)' : 'var(--text-muted)',
                  letterSpacing: '0.04em'
                }}>
                  {day.day_name || day.date?.split(' ')[0]}
                </span>
                {day.is_today && (
                  <span style={{
                    fontSize: 9.5,
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    padding: '1px 6px',
                    borderRadius: 10,
                    background: 'rgba(59, 130, 246, 0.15)',
                    color: 'var(--accent-blue)'
                  }}>
                    Today
                  </span>
                )}
              </div>

              {/* Date */}
              <div style={{
                fontSize: 13,
                fontWeight: 600,
                color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)'
              }}>
                {day.date}
              </div>

              {/* Total volume number */}
              <div style={{
                fontSize: 18,
                fontWeight: 700,
                fontFamily: 'JetBrains Mono, monospace',
                color: count > 0 ? 'var(--text-primary)' : 'var(--text-muted)'
              }}>
                {count} <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-muted)' }}>scans</span>
              </div>

              {/* Proportional Segmented Bar */}
              <div style={{
                width: '100%',
                height: 6,
                borderRadius: 3,
                background: count > 0 ? 'rgba(255, 255, 255, 0.08)' : 'var(--border-subtle)',
                overflow: 'hidden',
                display: 'flex'
              }}>
                {scamPct > 0 && (
                  <div style={{ width: `${scamPct}%`, background: 'var(--accent-red)' }} />
                )}
                {suspPct > 0 && (
                  <div style={{ width: `${suspPct}%`, background: 'var(--accent-yellow)' }} />
                )}
                {safePct > 0 && (
                  <div style={{ width: `${safePct}%`, background: 'var(--accent-green)' }} />
                )}
              </div>

              {/* Micro indicators */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                {scams > 0 && (
                  <span style={{ color: 'var(--accent-red)', fontWeight: 600 }}>
                    {scams} scam
                  </span>
                )}
                {suspicious > 0 && (
                  <span style={{ color: 'var(--accent-yellow)', fontWeight: 600 }}>
                    {suspicious} susp
                  </span>
                )}
                {safe > 0 && (
                  <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>
                    {safe} safe
                  </span>
                )}
                {count === 0 && (
                  <span style={{ color: 'var(--text-muted)' }}>No threats</span>
                )}
              </div>
            </button>
          )
        })}
      </div>

      {/* Selected Day Detailed Audit Card */}
      {activeDay && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 'var(--radius-md)',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
          fontSize: 12.5
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
              {activeDay.full_date || activeDay.date}:
            </span>
            <span style={{ color: 'var(--text-secondary)' }}>
              {activeDay.count > 0 ? (
                <>
                  <strong style={{ color: 'var(--text-primary)' }}>{activeDay.count}</strong> total scans evaluated (
                  <span style={{ color: 'var(--accent-red)', fontWeight: 600 }}>{activeDay.scams || 0} scams blocked</span>,{' '}
                  <span style={{ color: 'var(--accent-yellow)', fontWeight: 600 }}>{activeDay.suspicious || 0} suspicious</span>,{' '}
                  <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>{activeDay.safe || 0} safe</span>)
                </>
              ) : (
                'Zero threat activity recorded on this date. All communications remained clean.'
              )}
            </span>
          </div>

          <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
            Hover or click any date card to inspect daily threat logs
          </span>
        </div>
      )}
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
