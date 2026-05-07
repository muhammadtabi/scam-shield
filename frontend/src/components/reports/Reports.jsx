import { useState } from 'react'
import { api } from '../../api/client'

export default function Reports() {
  const [loadingPDF, setLoadingPDF] = useState(false)
  const [loadingCSV, setLoadingCSV] = useState(false)
  const [message,    setMessage]    = useState('')

  const handlePDF = async () => {
    setLoadingPDF(true); setMessage('')
    try {
      await api.downloadPDF()
      setMessage('✅ PDF downloaded successfully!')
    } catch (err) {
      setMessage('❌ ' + err.message)
    } finally {
      setLoadingPDF(false)
    }
  }

  const handleCSV = async () => {
    setLoadingCSV(true); setMessage('')
    try {
      await api.downloadCSV()
      setMessage('✅ CSV downloaded successfully!')
    } catch (err) {
      setMessage('❌ ' + err.message)
    } finally {
      setLoadingCSV(false)
    }
  }

  return (
    <div className="fade-in">
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontFamily: 'Syne', fontWeight: 800, fontSize: 28,
                     color: '#e2e8f0', marginBottom: 6 }}>Reports</h1>
        <p style={{ color: '#94a3b8', fontSize: 14 }}>
          Export your scam detection history
        </p>
      </div>

      {message && (
        <div style={{
          background: message.startsWith('✅') ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
          border: `1px solid ${message.startsWith('✅') ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
          borderRadius: 8, padding: '12px 16px', marginBottom: 20,
          color: message.startsWith('✅') ? '#22c55e' : '#ef4444', fontSize: 14
        }}>{message}</div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* PDF Report */}
        <div className="glass" style={{ padding: 32 }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>📄</div>
          <h2 style={{ fontFamily: 'Syne', fontWeight: 700, fontSize: 20,
                       color: '#e2e8f0', marginBottom: 8 }}>PDF Report</h2>
          <p style={{ color: '#94a3b8', fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
            Download a formatted PDF report with detection summaries,
            confidence scores, AI explanations, and visual statistics.
          </p>
          <div style={{ marginBottom: 20 }}>
            {['Detection summaries', 'Confidence scores', 'AI explanations',
              'Timestamps', 'Visual formatting'].map(f => (
              <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8,
                                    fontSize: 13, color: '#94a3b8', padding: '4px 0' }}>
                <span style={{ color: '#22c55e' }}>✓</span> {f}
              </div>
            ))}
          </div>
          <button className="btn-cyber" onClick={handlePDF} disabled={loadingPDF}
            style={{ width: '100%', display: 'flex', alignItems: 'center',
                     justifyContent: 'center', gap: 8 }}>
            {loadingPDF
              ? <><span className="loader" style={{ borderTopColor: '#020817' }}></span> Generating...</>
              : '⬇ Download PDF'}
          </button>
        </div>

        {/* CSV Report */}
        <div className="glass" style={{ padding: 32 }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>📊</div>
          <h2 style={{ fontFamily: 'Syne', fontWeight: 700, fontSize: 20,
                       color: '#e2e8f0', marginBottom: 8 }}>CSV Export</h2>
          <p style={{ color: '#94a3b8', fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
            Export raw detection data as CSV for analysis in Excel,
            Google Sheets, or any data analysis tool.
          </p>
          <div style={{ marginBottom: 20 }}>
            {['All detection records', 'Scam level & confidence',
              'Detection reasons', 'Timestamps', 'Excel compatible'].map(f => (
              <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8,
                                    fontSize: 13, color: '#94a3b8', padding: '4px 0' }}>
                <span style={{ color: '#22c55e' }}>✓</span> {f}
              </div>
            ))}
          </div>
          <button className="btn-cyber" onClick={handleCSV} disabled={loadingCSV}
            style={{ width: '100%', display: 'flex', alignItems: 'center',
                     justifyContent: 'center', gap: 8 }}>
            {loadingCSV
              ? <><span className="loader" style={{ borderTopColor: '#020817' }}></span> Exporting...</>
              : '⬇ Download CSV'}
          </button>
        </div>
      </div>

      {/* Info */}
      <div className="glass" style={{ padding: 20, marginTop: 20,
                                       display: 'flex', alignItems: 'center', gap: 14 }}>
        <span style={{ fontSize: 24 }}>💡</span>
        <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>
          Reports include up to your last <strong style={{ color: '#e2e8f0' }}>50 detections</strong>.
          Use these reports for academic documentation, security audits, or presenting your FYP results.
          The PDF is formatted for professional submission.
        </div>
      </div>
    </div>
  )
}
