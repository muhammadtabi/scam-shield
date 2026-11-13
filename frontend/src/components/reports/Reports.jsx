import { useState } from 'react'
import { api } from '../../api/client'
import {
  FileText,
  FileSpreadsheet,
  Download,
  Check,
  Info,
  CheckCircle2,
  AlertCircle
} from 'lucide-react'

export default function Reports() {
  const [loadingPDF, setLoadingPDF] = useState(false)
  const [loadingCSV, setLoadingCSV] = useState(false)
  const [message,    setMessage]    = useState('')
  const [isSuccess,  setIsSuccess]  = useState(true)

  const handlePDF = async () => {
    setLoadingPDF(true); setMessage('')
    try {
      await api.downloadPDF()
      setIsSuccess(true)
      setMessage('PDF report generated and downloaded.')
    } catch (err) {
      setIsSuccess(false)
      setMessage(err.message || 'Failed to download PDF.')
    } finally {
      setLoadingPDF(false)
    }
  }

  const handleCSV = async () => {
    setLoadingCSV(true); setMessage('')
    try {
      await api.downloadCSV()
      setIsSuccess(true)
      setMessage('CSV export downloaded successfully.')
    } catch (err) {
      setIsSuccess(false)
      setMessage(err.message || 'Failed to export CSV.')
    } finally {
      setLoadingCSV(false)
    }
  }

  return (
    <div className="fade-in">
      <div className="page-header stagger stagger-1">
        <h1 className="page-title">Reports & Export</h1>
        <p className="page-subtitle">
          Export threat detection logs for documentation and compliance audits
        </p>
      </div>

      {message && (
        <div className="stagger stagger-2" style={{
          background: isSuccess ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
          border: `1px solid ${isSuccess ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
          borderRadius: 'var(--radius-md)', padding: '10px 14px', marginBottom: 18,
          color: isSuccess ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: 12.5,
          display: 'flex', alignItems: 'center', gap: 8
        }}>
          {isSuccess ? <CheckCircle2 size={15} /> : <AlertCircle size={15} />}
          <span>{message}</span>
        </div>
      )}

      <div className="report-grid">
        <div className="card stagger stagger-3" style={{ padding: '22px 24px' }}>
          <div style={{
            width: 38, height: 38, borderRadius: 'var(--radius-md)',
            background: 'rgba(59, 130, 246, 0.1)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            marginBottom: 14
          }}>
            <FileText size={18} color="var(--accent-primary)" />
          </div>
          <h2 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 16.5,
                       color: 'var(--text-primary)', marginBottom: 6, letterSpacing: '-0.015em' }}>
            PDF Security Report
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.5, marginBottom: 18 }}>
            Structured document detailing recent scans, verdict summaries, confidence scores, and rule explanations.
          </p>
          <div style={{ marginBottom: 20 }}>
            {['Detection summaries', 'Confidence scores', 'Factor explanations',
              'Timestamps and sender IDs', 'Formatted summary layout'].map(f => (
              <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 7,
                                    fontSize: 12.5, color: 'var(--text-secondary)', padding: '4px 0' }}>
                <Check size={13} color="var(--accent-green)" />
                <span>{f}</span>
              </div>
            ))}
          </div>
          <button className="btn-primary" onClick={handlePDF} disabled={loadingPDF}
            type="button"
            style={{ width: '100%', padding: '9px 16px' }}>
            {loadingPDF ? (
              <>
                <span className="loader" style={{ borderTopColor: '#ffffff' }}></span>
                <span>Generating PDF...</span>
              </>
            ) : (
              <>
                <Download size={14} />
                <span>Download PDF Report</span>
              </>
            )}
          </button>
        </div>

        <div className="card stagger stagger-4" style={{ padding: '22px 24px' }}>
          <div style={{
            width: 38, height: 38, borderRadius: 'var(--radius-md)',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            marginBottom: 14
          }}>
            <FileSpreadsheet size={18} color="var(--accent-green)" />
          </div>
          <h2 style={{ fontFamily: 'Plus Jakarta Sans', fontWeight: 700, fontSize: 16.5,
                       color: 'var(--text-primary)', marginBottom: 6, letterSpacing: '-0.015em' }}>
            CSV Data Export
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.5, marginBottom: 18 }}>
            Export tabular raw detection records for spreadsheet review, SIEM ingestion, or data analysis pipelines.
          </p>
          <div style={{ marginBottom: 20 }}>
            {['All detection records', 'Risk level & confidence',
              'Extracted indicators & reasons', 'UTC timestamps', 'RFC-compliant CSV format'].map(f => (
              <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 7,
                                    fontSize: 12.5, color: 'var(--text-secondary)', padding: '4px 0' }}>
                <Check size={13} color="var(--accent-green)" />
                <span>{f}</span>
              </div>
            ))}
          </div>
          <button className="btn-primary" onClick={handleCSV} disabled={loadingCSV}
            type="button"
            style={{ width: '100%', padding: '9px 16px' }}>
            {loadingCSV ? (
              <>
                <span className="loader" style={{ borderTopColor: '#ffffff' }}></span>
                <span>Exporting CSV...</span>
              </>
            ) : (
              <>
                <Download size={14} />
                <span>Export CSV File</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Info */}
      <div className="card stagger stagger-5" style={{ padding: '14px 18px', marginTop: 18,
                                       display: 'flex', alignItems: 'center', gap: 12 }}>
        <Info size={17} color="var(--accent-primary)" style={{ flexShrink: 0 }} />
        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          Exports include your <strong style={{ color: 'var(--text-primary)' }}>50 most recent detections</strong>.
          Use these records for security reviews, incident response tracking, and audit logging.
        </div>
      </div>
    </div>
  )
}
