import { useState, useEffect } from 'react'
import { api } from '../../api/client'
import {
  GraduationCap,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RotateCcw,
  Award,
  Flame,
  Mail,
  Smartphone,
  Globe,
  ArrowRight,
  ArrowLeft,
  Check,
  Sparkles
} from 'lucide-react'

export default function Training() {
  const [scenarios, setScenarios] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filterType, setFilterType] = useState('all')
  const [currentIndex, setCurrentIndex] = useState(0)

  // Interactive submission state
  const [selectedVerdict, setSelectedVerdict] = useState(null)
  const [selectedClues, setSelectedClues] = useState([])
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [resultsByScenario, setResultsByScenario] = useState({})
  const [isResetting, setIsResetting] = useState(false)

  const loadData = async () => {
    try {
      setLoading(true)
      setError('')
      const [scenariosData, statsData] = await Promise.all([
        api.getTrainingScenarios(),
        api.getTrainingStats()
      ])
      setScenarios(scenariosData || [])
      setStats(statsData)
    } catch (err) {
      setError(err.message || 'Failed to load training modules')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const filteredScenarios = scenarios.filter(s => {
    if (filterType === 'all') return true
    return s.type === filterType
  })

  // Keep index in bounds when filter changes
  useEffect(() => {
    setCurrentIndex(0)
  }, [filterType])

  const currentScenario = filteredScenarios[currentIndex] || null
  const currentResult = currentScenario ? resultsByScenario[currentScenario.id] : null

  // Reset local interactive inputs when switching scenarios
  useEffect(() => {
    if (!currentScenario) return
    const existing = resultsByScenario[currentScenario.id]
    if (existing) {
      setSelectedVerdict(existing.user_verdict)
      setSelectedClues([])
    } else {
      setSelectedVerdict(null)
      setSelectedClues([])
    }
  }, [currentIndex, currentScenario, resultsByScenario])

  const handleToggleClue = (clue) => {
    if (currentResult) return // Read-only once evaluated
    setSelectedClues(prev => 
      prev.includes(clue) ? prev.filter(c => c !== clue) : [...prev, clue]
    )
  }

  const handleSubmit = async () => {
    if (!currentScenario || !selectedVerdict || isSubmitting) return

    try {
      setIsSubmitting(true)
      const res = await api.submitTrainingAnswer({
        scenario_id: currentScenario.id,
        user_verdict: selectedVerdict,
        selected_clues: selectedClues
      })

      setResultsByScenario(prev => ({
        ...prev,
        [currentScenario.id]: res
      }))

      if (res.user_stats) {
        setStats(res.user_stats)
      }
    } catch (err) {
      setError(err.message || 'Failed to submit evaluation')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleReset = async () => {
    if (!window.confirm('Reset all training progress and clear current scores?')) return
    try {
      setIsResetting(true)
      await api.resetTraining()
      setResultsByScenario({})
      setSelectedVerdict(null)
      setSelectedClues([])
      await loadData()
    } catch (err) {
      setError(err.message || 'Failed to reset progress')
    } finally {
      setIsResetting(false)
    }
  }

  const handleNext = () => {
    if (currentIndex < filteredScenarios.length - 1) {
      setCurrentIndex(currentIndex + 1)
    }
  }

  const handlePrev = () => {
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1)
    }
  }

  const getDifficultyBadge = (difficulty) => {
    const map = {
      beginner: { label: 'Beginner', bg: 'rgba(16, 185, 129, 0.1)', text: '#10b981', border: 'rgba(16, 185, 129, 0.2)' },
      intermediate: { label: 'Intermediate', bg: 'rgba(245, 158, 11, 0.1)', text: '#f59e0b', border: 'rgba(245, 158, 11, 0.2)' },
      advanced: { label: 'Advanced', bg: 'rgba(239, 68, 68, 0.1)', text: '#ef4444', border: 'rgba(239, 68, 68, 0.2)' }
    }
    const config = map[difficulty] || map.beginner
    return (
      <span style={{
        padding: '3px 8px',
        borderRadius: 'var(--radius-sm)',
        fontSize: '11px',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        background: config.bg,
        color: config.text,
        border: `1px solid ${config.border}`
      }}>
        {config.label}
      </span>
    )
  }

  const getTypeIcon = (type) => {
    if (type === 'email') return <Mail size={14} />
    if (type === 'sms') return <Smartphone size={14} />
    return <Globe size={14} />
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', gap: 12, color: 'var(--text-secondary)' }}>
        <span className="loader"></span>
        <span>Loading training scenarios...</span>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: 'var(--radius-md)',
              background: 'rgba(59, 130, 246, 0.12)',
              border: '1px solid rgba(59, 130, 246, 0.24)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-blue)'
            }}>
              <GraduationCap size={18} />
            </div>
            <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              Phishing & Scam Awareness Training
            </h1>
          </div>
          <p style={{ fontSize: 13.5, color: 'var(--text-secondary)' }}>
            Interactive threat analysis scenarios. Test your suspicion against real attack vectors and compare with automated detection models.
          </p>
        </div>

        <button
          onClick={handleReset}
          disabled={isResetting}
          className="btn-secondary"
          title="Reset your score and progress"
          type="button"
        >
          <RotateCcw size={14} />
          <span>{isResetting ? 'Resetting...' : 'Reset Progress'}</span>
        </button>
      </div>

      {error && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 'var(--radius-md)',
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.25)',
          color: '#ef4444',
          fontSize: 13,
          display: 'flex',
          alignItems: 'center',
          gap: 8
        }}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Metrics Ribbon */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: 14
      }}>
        <div className="card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 38,
            height: 38,
            borderRadius: 'var(--radius-md)',
            background: 'rgba(59, 130, 246, 0.1)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-blue)'
          }}>
            <Award size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Security Rank
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
              {stats?.rank_tier || 'Security Cadet'}
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 38,
            height: 38,
            borderRadius: 'var(--radius-md)',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-green)'
          }}>
            <ShieldCheck size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Accuracy Rate
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
              {stats?.accuracy_percent != null ? `${stats.accuracy_percent}%` : '0%'}
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 38,
            height: 38,
            borderRadius: 'var(--radius-md)',
            background: 'rgba(245, 158, 11, 0.1)',
            border: '1px solid rgba(245, 158, 11, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent-yellow)'
          }}>
            <Flame size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Current Streak
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
              {stats?.current_streak || 0} in a row
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 38,
            height: 38,
            borderRadius: 'var(--radius-md)',
            background: 'rgba(161, 161, 170, 0.1)',
            border: '1px solid rgba(161, 161, 170, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--text-primary)'
          }}>
            <CheckCircle2 size={20} />
          </div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Completed
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
              {stats?.total_attempted || 0} / {scenarios.length}
            </div>
          </div>
        </div>
      </div>

      {/* Filter Tabs & Navigation Carousel */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
        paddingBottom: 4
      }}>
        {/* Type Filter */}
        <div style={{
          display: 'inline-flex',
          padding: 3,
          background: 'var(--bg-secondary)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)'
        }}>
          {[
            { id: 'all', label: 'All Modules' },
            { id: 'email', label: 'Email Phishing' },
            { id: 'sms', label: 'SMS Smishing' },
            { id: 'url', label: 'Malicious URLs' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setFilterType(tab.id)}
              type="button"
              style={{
                padding: '6px 12px',
                fontSize: 12.5,
                fontWeight: 500,
                borderRadius: 'var(--radius-sm)',
                border: 'none',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                background: filterType === tab.id ? 'var(--bg-card)' : 'transparent',
                color: filterType === tab.id ? 'var(--text-primary)' : 'var(--text-secondary)',
                boxShadow: filterType === tab.id ? 'var(--shadow-sm)' : 'none'
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Carousel Numbers */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {filteredScenarios.map((scenario, idx) => {
            const res = resultsByScenario[scenario.id]
            const isCurrent = idx === currentIndex

            let dotColor = 'var(--text-muted)'
            let borderStyle = '1px solid var(--border)'
            if (res) {
              dotColor = res.is_correct ? 'var(--accent-green)' : 'var(--accent-red)'
              borderStyle = res.is_correct
                ? '1px solid rgba(16, 185, 129, 0.4)'
                : '1px solid rgba(239, 68, 68, 0.4)'
            }

            return (
              <button
                key={scenario.id}
                onClick={() => setCurrentIndex(idx)}
                type="button"
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 'var(--radius-sm)',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: isCurrent ? 'var(--bg-elevated)' : 'var(--bg-card)',
                  color: isCurrent ? 'var(--text-primary)' : 'var(--text-secondary)',
                  border: isCurrent ? '1px solid var(--accent-blue)' : borderStyle,
                  position: 'relative'
                }}
              >
                {idx + 1}
                {res && (
                  <span style={{
                    position: 'absolute',
                    top: 2,
                    right: 2,
                    width: 5,
                    height: 5,
                    borderRadius: '50%',
                    backgroundColor: dotColor
                  }} />
                )}
              </button>
            )
          })}
        </div>
      </div>

      {/* Main Scenario Workspace */}
      {currentScenario ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.35fr) minmax(320px, 1fr)', gap: 20 }}>
          {/* Left: Realistic Scenario Mock Container */}
          <div className="card" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Scenario Meta */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="badge" style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                  {getTypeIcon(currentScenario.type)}
                  <span style={{ textTransform: 'uppercase' }}>{currentScenario.type}</span>
                </span>
                {getDifficultyBadge(currentScenario.difficulty)}
              </div>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Scenario {currentIndex + 1} of {filteredScenarios.length}
              </span>
            </div>

            <div>
              <h2 style={{ fontSize: 17, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                {currentScenario.title}
              </h2>
              <p style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>
                Review the message details below as if it arrived in your real communications.
              </p>
            </div>

            {/* Email Mock */}
            {currentScenario.type === 'email' && (
              <div style={{
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                overflow: 'hidden'
              }}>
                <div style={{
                  padding: '12px 16px',
                  background: 'var(--bg-elevated)',
                  borderBottom: '1px solid var(--border)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5 }}>
                    <span style={{ color: 'var(--text-muted)', width: 50 }}>From:</span>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {currentScenario.sender || 'Unknown Sender'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5 }}>
                    <span style={{ color: 'var(--text-muted)', width: 50 }}>Subject:</span>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {currentScenario.subject || '(No Subject)'}
                    </span>
                  </div>
                </div>
                <div style={{
                  padding: '18px 20px',
                  fontSize: 13.5,
                  lineHeight: 1.6,
                  color: 'var(--text-primary)',
                  whiteSpace: 'pre-wrap',
                  fontFamily: 'Inter, sans-serif'
                }}>
                  {currentScenario.content}
                </div>
              </div>
            )}

            {/* SMS Mock */}
            {currentScenario.type === 'sms' && (
              <div style={{
                borderRadius: 'var(--radius-lg)',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                padding: '24px 20px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 16
              }}>
                <div style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '4px 12px',
                  borderRadius: 20,
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border)',
                  fontSize: 12,
                  fontFamily: 'JetBrains Mono, monospace',
                  color: 'var(--text-secondary)'
                }}>
                  <Smartphone size={13} />
                  <span>Sender: {currentScenario.sender || 'SMS Alert'}</span>
                </div>

                <div style={{
                  maxWidth: '85%',
                  alignSelf: 'flex-start',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  padding: '14px 18px',
                  borderRadius: '16px 16px 16px 4px',
                  fontSize: 13.5,
                  lineHeight: 1.55,
                  color: 'var(--text-primary)',
                  whiteSpace: 'pre-wrap'
                }}>
                  {currentScenario.content}
                </div>
              </div>
            )}

            {/* URL Mock */}
            {currentScenario.type === 'url' && (
              <div style={{
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                overflow: 'hidden'
              }}>
                {/* Simulated Browser Bar */}
                <div style={{
                  padding: '10px 14px',
                  background: 'var(--bg-elevated)',
                  borderBottom: '1px solid var(--border)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10
                }}>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444', opacity: 0.7 }} />
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b', opacity: 0.7 }} />
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981', opacity: 0.7 }} />
                  </div>
                  <div style={{
                    flex: 1,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '4px 10px',
                    fontSize: 12,
                    fontFamily: 'JetBrains Mono, monospace',
                    color: 'var(--text-primary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}>
                    <Globe size={13} style={{ flexShrink: 0, color: 'var(--text-muted)' }} />
                    <span>{currentScenario.url || 'https://unknown-domain.example'}</span>
                  </div>
                </div>

                <div style={{
                  padding: '24px 20px',
                  fontSize: 13.5,
                  lineHeight: 1.6,
                  color: 'var(--text-primary)',
                  whiteSpace: 'pre-wrap'
                }}>
                  {currentScenario.content}
                </div>
              </div>
            )}

            {/* Carousel Prev/Next Buttons */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 'auto', paddingTop: 12 }}>
              <button
                onClick={handlePrev}
                disabled={currentIndex === 0}
                className="btn-secondary"
                type="button"
              >
                <ArrowLeft size={14} />
                <span>Previous</span>
              </button>

              <button
                onClick={handleNext}
                disabled={currentIndex === filteredScenarios.length - 1}
                className="btn-secondary"
                type="button"
              >
                <span>Next</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {/* Right: Assessment & Evaluation Panel */}
          <div className="card" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div>
              <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)' }}>
                Threat Assessment
              </h3>
              <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginTop: 2 }}>
                Make your determination and select any suspicious indicators.
              </p>
            </div>

            {/* Interactive Verdict Selection */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Your Verdict
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <button
                  type="button"
                  onClick={() => !currentResult && setSelectedVerdict('safe')}
                  disabled={Boolean(currentResult)}
                  style={{
                    padding: '12px 14px',
                    borderRadius: 'var(--radius-md)',
                    border: selectedVerdict === 'safe'
                      ? '2px solid var(--accent-green)'
                      : '1px solid var(--border)',
                    background: selectedVerdict === 'safe'
                      ? 'rgba(16, 185, 129, 0.12)'
                      : 'var(--bg-secondary)',
                    color: selectedVerdict === 'safe' ? '#10b981' : 'var(--text-primary)',
                    cursor: currentResult ? 'default' : 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: 6,
                    fontWeight: 600,
                    fontSize: 13,
                    transition: 'all 0.15s ease'
                  }}
                >
                  <ShieldCheck size={20} />
                  <span>Legitimate</span>
                </button>

                <button
                  type="button"
                  onClick={() => !currentResult && setSelectedVerdict('scam')}
                  disabled={Boolean(currentResult)}
                  style={{
                    padding: '12px 14px',
                    borderRadius: 'var(--radius-md)',
                    border: selectedVerdict === 'scam'
                      ? '2px solid var(--accent-red)'
                      : '1px solid var(--border)',
                    background: selectedVerdict === 'scam'
                      ? 'rgba(239, 68, 68, 0.12)'
                      : 'var(--bg-secondary)',
                    color: selectedVerdict === 'scam' ? '#ef4444' : 'var(--text-primary)',
                    cursor: currentResult ? 'default' : 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: 6,
                    fontWeight: 600,
                    fontSize: 13,
                    transition: 'all 0.15s ease'
                  }}
                >
                  <ShieldAlert size={20} />
                  <span>Phishing / Scam</span>
                </button>
              </div>
            </div>

            {/* Clue Options Checklist */}
            {currentScenario.clue_options && currentScenario.clue_options.length > 0 && (
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Suspicious Indicators (Select all that apply)
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {currentScenario.clue_options.map((clue, idx) => {
                    const isSelected = selectedClues.includes(clue)
                    const isGroundTruth = currentResult?.correct_clues?.includes(clue)

                    let checkBg = isSelected ? 'var(--accent-blue)' : 'transparent'
                    let borderCol = isSelected ? 'var(--accent-blue)' : 'var(--border)'
                    
                    if (currentResult) {
                      if (isGroundTruth) {
                        checkBg = 'var(--accent-green)'
                        borderCol = 'var(--accent-green)'
                      } else if (isSelected && !isGroundTruth) {
                        checkBg = 'var(--accent-red)'
                        borderCol = 'var(--accent-red)'
                      }
                    }

                    return (
                      <label
                        key={idx}
                        onClick={() => handleToggleClue(clue)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 10,
                          padding: '8px 12px',
                          borderRadius: 'var(--radius-sm)',
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border)',
                          cursor: currentResult ? 'default' : 'pointer',
                          fontSize: 13,
                          color: 'var(--text-primary)',
                          userSelect: 'none',
                          transition: 'background 0.15s ease'
                        }}
                      >
                        <div style={{
                          width: 18,
                          height: 18,
                          borderRadius: 4,
                          border: `1.5px solid ${borderCol}`,
                          background: checkBg,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: '#fff',
                          flexShrink: 0
                        }}>
                          {(isSelected || (currentResult && isGroundTruth)) && <Check size={12} strokeWidth={3} />}
                        </div>
                        <span style={{ flex: 1 }}>{clue}</span>
                        {currentResult && isGroundTruth && (
                          <span style={{ fontSize: 11, color: 'var(--accent-green)', fontWeight: 600 }}>
                            +25 XP
                          </span>
                        )}
                      </label>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Submission Action */}
            {!currentResult ? (
              <button
                type="button"
                onClick={handleSubmit}
                disabled={!selectedVerdict || isSubmitting}
                className="btn-primary"
                style={{ padding: '11px 16px', marginTop: 'auto' }}
              >
                {isSubmitting ? (
                  <>
                    <span className="loader"></span>
                    <span>Analyzing Assessment...</span>
                  </>
                ) : (
                  <>
                    <Sparkles size={15} />
                    <span>Submit Assessment</span>
                  </>
                )}
              </button>
            ) : (
              /* Evaluation Feedback Section */
              <div style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 14,
                padding: '16px',
                borderRadius: 'var(--radius-md)',
                background: currentResult.is_correct ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                border: currentResult.is_correct ? '1px solid rgba(16, 185, 129, 0.25)' : '1px solid rgba(239, 68, 68, 0.25)',
                marginTop: 'auto'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {currentResult.is_correct ? (
                      <CheckCircle2 size={18} color="var(--accent-green)" />
                    ) : (
                      <XCircle size={18} color="var(--accent-red)" />
                    )}
                    <span style={{
                      fontWeight: 700,
                      fontSize: 14,
                      color: currentResult.is_correct ? 'var(--accent-green)' : 'var(--accent-red)'
                    }}>
                      {currentResult.is_correct ? 'Correct Assessment' : 'Incorrect Assessment'}
                    </span>
                  </div>
                  <span style={{
                    fontSize: 12,
                    fontWeight: 700,
                    fontFamily: 'JetBrains Mono, monospace',
                    color: currentResult.is_correct ? 'var(--accent-green)' : 'var(--accent-red)'
                  }}>
                    +{currentResult.total_score} XP
                  </span>
                </div>

                <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                  {currentResult.explanation}
                </div>

                {/* Comparative Model Analysis */}
                <div style={{
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  fontSize: 12,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-secondary)' }}>
                    <span>Automated Model Confidence:</span>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {Math.round(currentResult.ml_confidence * 100)}%
                    </span>
                  </div>
                  {currentResult.ml_reasons && currentResult.ml_reasons.length > 0 && (
                    <div style={{ color: 'var(--text-muted)', fontSize: 11.5, marginTop: 2 }}>
                      Signals: {currentResult.ml_reasons.join(', ')}
                    </div>
                  )}
                </div>

                {/* Key Takeaway Box */}
                <div style={{
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(59, 130, 246, 0.08)',
                  border: '1px solid rgba(59, 130, 246, 0.2)',
                  fontSize: 12.5,
                  color: 'var(--text-primary)'
                }}>
                  <strong style={{ color: 'var(--accent-blue)', display: 'block', marginBottom: 2 }}>
                    Key Takeaway:
                  </strong>
                  {currentResult.key_takeaway}
                </div>

                {/* Next button shortcut */}
                {currentIndex < filteredScenarios.length - 1 && (
                  <button
                    onClick={handleNext}
                    className="btn-primary"
                    type="button"
                    style={{ marginTop: 4 }}
                  >
                    <span>Proceed to Next Scenario</span>
                    <ArrowRight size={14} />
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
          No scenarios available for the selected filter.
        </div>
      )}
    </div>
  )
}

