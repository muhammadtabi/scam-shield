/**
 * Formats date/time strings or epoch timestamps into user's local timezone.
 * Handles naive UTC ISO strings (without 'Z'), timezone-aware ISO strings,
 * RFC 2822 email date headers, and numeric epoch timestamps.
 */
export function formatLocalDateTime(val, options = {}) {
  if (!val) return ''
  const num = Number(val)
  let d
  if (!isNaN(num) && num > 1000000000) {
    d = new Date(num < 10000000000 ? num * 1000 : num)
  } else {
    const str = String(val).trim()
    const normalized =
      !str.endsWith('Z') &&
      !/[+-]\d{2}(:\d{2})?$/.test(str) &&
      /^\d{4}-\d{2}-\d{2}/.test(str)
        ? `${str}Z`
        : str
    d = new Date(normalized)
  }
  return isNaN(d.getTime()) ? String(val) : d.toLocaleString(undefined, options)
}

