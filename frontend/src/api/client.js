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
  const data = await res.json()
  
  if (res.status === 401) {
    localStorage.removeItem('token')
    window.location.href = '/'
    throw new Error('Session expired. Please log in again.')
  }
  
  if (!res.ok) throw new Error(extractErrorMessage(data))
  return data
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
  downloadCSV: async () => {
    const token = localStorage.getItem('token')
    const res = await fetch(`${BASE_URL}/api/reports/csv`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    const blob = await res.blob()
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = 'scam_report.csv'; a.click()
  },
  downloadPDF: async () => {
    const token = localStorage.getItem('token')
    const res = await fetch(`${BASE_URL}/api/reports/pdf`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    const blob = await res.blob()
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = 'scam_report.pdf'; a.click()
  }
}
