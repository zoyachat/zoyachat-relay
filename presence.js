/**
 * Presence — online/offline status tracking.
 * Notifies contacts when a user's status changes.
 */
const db = require('./db')

/**
 * Mark user as online and notify their contacts.
 * @param {string} userId
 * @param {function} pushToUser - (userId, msg) => void
 */
function setOnline(userId, pushToUser) {
  db.setPresence(userId, true)
  notifyContacts(userId, true, pushToUser)
}

/**
 * Mark user as offline and notify their contacts.
 */
function setOffline(userId, pushToUser) {
  db.setPresence(userId, false)
  notifyContacts(userId, false, pushToUser)
}

/**
 * Get presence info for a list of user IDs.
 * @returns {{ userId, isOnline, lastSeen }[]}
 */
function getPresence(userIds) {
  if (!userIds?.length) return []
  return db.getPresence(userIds).map(p => ({
    userId: p.user_id,
    isOnline: !!p.is_online,
    lastSeen: p.last_seen,
  }))
}

/**
 * Notify all of userId's accepted contacts about their presence change.
 */
function notifyContacts(userId, isOnline, pushToUser) {
  const contacts = db.getContacts(userId)
  const msg = { type: 'presence', userId, isOnline, lastSeen: Math.floor(Date.now() / 1000) }
  for (const c of contacts) {
    pushToUser(c.contact_id, msg)
  }
}

module.exports = { setOnline, setOffline, getPresence }
