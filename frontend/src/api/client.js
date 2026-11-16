const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const extractErrorMessage = (data) => {
  if (!data) return 'Request failed'
  if (typeof data.detail === 'string' && data.detail.trim()) return data.detail
  if (Array.isArray(data.detail) && data.detail.length) {
    return data.detail
      .map(item => item?.msg || item?.message)
      .filter(Boolean)
      .join('; ') || 'Request failed'
  }
  if (Array.isArray(data.errors) && data.errors.length) {
    return data.errors.join('; ')
  }
  return 'Request failed'
}

const getHeaders = () => {
  const token = localStorage.getItem('token')
  return {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` })
  }
}

const request = async (method, path, body = null) => {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: getHeaders(),
    ...(body && { body: JSON.stringify(body) })
  })
  
  if (res.status === 401) {
    localStorage.removeItem('token')
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    }
    throw new Error('Session expired. Please log in again.')
  }

  const data = await res.json()
  if (!res.ok) throw new Error(extractErrorMessage(data))
  return data
}

const triggerBlobDownload = async (path, defaultFilename) => {
  const token = localStorage.getItem('token')
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      ...(token && { Authorization: `Bearer ${token}` })
    }
  })

  if (res.status === 401) {
    localStorage.removeItem('token')
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    }
    throw new Error('Session expired. Please log in again.')
  }

  if (!res.ok) {
    let errorMsg = 'Failed to download report'
    try {
      const errData = await res.json()
      errorMsg = extractErrorMessage(errData)
    } catch {
      // ignore JSON parse errors on binary/non-JSON responses
    }
    throw new Error(errorMsg)
  }

  const blob = await res.blob()
  const objectUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = objectUrl
  a.download = defaultFilename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)
}

export const api = {
  register: (data)   => request('POST', '/api/auth/register', data),
  login:    (data)   => request('POST', '/api/auth/login', data),
  getMe:    ()       => request('GET',  '/api/auth/me'),
  detectEmail: (data) => request('POST', '/api/detect/email', data),
  detectSMS:   (data) => request('POST', '/api/detect/sms',   data),
  detectURL:   (data) => request('POST', '/api/detect/url',   data),
  getHistory:  (limit = 20, skip = 0) =>
    request('GET', `/api/detect/history?limit=${limit}&skip=${skip}`),
  deleteDetection: (id) => request('DELETE', `/api/detect/history/${id}`),
  getStats: () => request('GET', '/api/dashboard/stats'),
  getGmailStatus: () => request('GET', '/api/gmail/status'),
  getGmailConnectUrl: () => request('GET', '/api/gmail/connect'),
  connectGmail: (data) => request('POST', '/api/gmail/callback', data),
  connectGmailImap: (data) => request('POST', '/api/gmail/connect-imap', data),
  syncGmail: () => request('POST', '/api/gmail/sync'),
  getGmailInbox: (limit = 30) => request('GET', `/api/gmail/inbox?limit=${limit}`),
  fetchGmailEmail: (id) => request('GET', `/api/gmail/message/${id}`),
  scanGmailEmail: (id) => request('POST', `/api/gmail/message/${id}/scan`),
  disconnectGmail: () => request('DELETE', '/api/gmail/disconnect'),
  getSmsStatus: () => request('GET', '/api/sms/status'),
  connectSmsPhone: (phoneNumber) => request('POST', '/api/sms/connect', { phone_number: phoneNumber }),
  disconnectSmsPhone: () => request('POST', '/api/sms/disconnect'),
  getSmsInbox: (scamLevel = null, search = null, page = 1) => {
    const params = new URLSearchParams()
    if (scamLevel) params.append('scam_level', scamLevel)
    if (search) params.append('search', search)
    if (page) params.append('page', String(page))
    const qs = params.toString()
    return request('GET', `/api/sms/inbox${qs ? `?${qs}` : ''}`)
  },
  getSmsMessage: (id) => request('GET', `/api/sms/messages/${id}`),
  deleteSmsMessage: (id) => request('DELETE', `/api/sms/messages/${id}`),
  simulateSms: (data) => request('POST', '/api/sms/simulate', data),
  importSmsBatch: (messages) => request('POST', '/api/sms/sync-batch', { messages }),
  downloadCSV: () => triggerBlobDownload('/api/reports/csv', 'scam_report.csv'),
  downloadPDF: () => triggerBlobDownload('/api/reports/pdf', 'scam_report.pdf')
}
