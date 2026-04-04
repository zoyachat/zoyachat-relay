/**
 * Analytics — lightweight event tracking for stats dashboard.
 */
const db = require('./db')

function track(eventType, userId, metadata, ip) {
  try {
    db.insertAnalytics(eventType, userId, typeof metadata === 'object' ? JSON.stringify(metadata) : metadata, ip)
  } catch (e) {
    console.warn('[analytics] track error:', e.message)
  }
}

module.exports = { track }
