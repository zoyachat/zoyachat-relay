/**
 * Friend handler — send/accept/reject friend requests, search users.
 */
const db = require('./db')

function sendFriendRequest(fromUserId, toUserId, message, pushToUser) {
  if (fromUserId === toUserId) return { ok: false, error: 'CANNOT_ADD_SELF' }

  const toUser = db.getUserById(toUserId)
  if (!toUser) return { ok: false, error: 'USER_NOT_FOUND' }

  // Check if already contacts
  const existing = db.getContact(fromUserId, toUserId)
  if (existing?.status === 'accepted') return { ok: false, error: 'ALREADY_CONTACTS' }

  // Check for existing pending request
  const pending = db.getFriendRequests(toUserId, 'pending')
  const alreadySent = pending.find(r => r.from_user === fromUserId)
  if (alreadySent) return { ok: false, error: 'ALREADY_SENT' }

  const fromUser = db.getUserById(fromUserId)
  const req = db.createFriendRequest(fromUserId, toUserId, fromUser?.display_name || '', message || '')

  pushToUser(toUserId, {
    type: 'friend_request',
    requestId: req.lastInsertRowid,
    from: fromUserId,
    fromName: fromUser?.display_name || '',
    fromColor: fromUser?.avatar_color || '#8b5cf6',
    message: message || '',
  })

  return { ok: true, requestId: req.lastInsertRowid }
}

function acceptFriendRequest(requestId, userId, pushToUser) {
  const req = db.getFriendRequest(requestId)
  if (!req) return { ok: false, error: 'NOT_FOUND' }
  if (req.to_user !== userId) return { ok: false, error: 'NOT_AUTHORIZED' }
  if (req.status !== 'pending') return { ok: false, error: 'ALREADY_PROCESSED' }

  db.updateFriendRequest(requestId, 'accepted')

  // Create bidirectional contacts
  db.addContact(req.from_user, req.to_user, 'accepted')
  db.addContact(req.to_user, req.from_user, 'accepted')

  const acceptor = db.getUserById(userId)
  pushToUser(req.from_user, {
    type: 'friend_accepted',
    userId,
    displayName: acceptor?.display_name || '',
    avatarColor: acceptor?.avatar_color || '#8b5cf6',
  })

  return { ok: true }
}

function rejectFriendRequest(requestId, userId) {
  const req = db.getFriendRequest(requestId)
  if (!req) return { ok: false, error: 'NOT_FOUND' }
  if (req.to_user !== userId) return { ok: false, error: 'NOT_AUTHORIZED' }
  if (req.status !== 'pending') return { ok: false, error: 'ALREADY_PROCESSED' }

  db.updateFriendRequest(requestId, 'rejected')
  return { ok: true }
}

function listFriendRequests(userId) {
  return db.getFriendRequests(userId, 'pending')
}

function friendRequestCount(userId) {
  return db.getPendingFriendRequestCount(userId)
}

function searchUsers(query) {
  if (!query || query.length < 2) return []
  return db.searchUsers(query, 20)
}

module.exports = { sendFriendRequest, acceptFriendRequest, rejectFriendRequest, listFriendRequests, friendRequestCount, searchUsers }
