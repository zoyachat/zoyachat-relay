/**
 * Message handler — 1v1 and group message processing.
 * Stores messages, pushes to online users, handles delivery status.
 */
const { v4: uuidv4 } = require('uuid')
const db = require('./db')

/**
 * Handle a direct (1v1) message.
 * @param {string} fromUserId
 * @param {object} msg - { to, content, msgType, messageId, fileId, fileName, fileSize, replyTo }
 * @param {function} pushToUser - (userId, msg) => delivered:boolean
 * @returns {{ ok, messageId, status }}
 */
function handleDirectMessage(fromUserId, msg, pushToUser, senderDeviceId) {
  const { to, content, msgType, messageId, fileId, fileName, fileSize, replyTo } = msg
  if (!to || (!content && !fileId)) return { ok: false, error: 'MISSING_FIELDS' }

  const mid = messageId || uuidv4()
  const timestamp = Date.now()

  // Store message
  db.insertMessage(mid, fromUserId, to, null, content || '', msgType || 'text', fileId, fileName, fileSize, replyTo)
  db.setMessageStatus(mid, fromUserId, 'sent')

  // Get sender info for the push
  const sender = db.getUserById(fromUserId)
  const pushMsg = {
    type: 'message',
    messageId: mid,
    from: fromUserId,
    fromName: sender?.display_name || '',
    fromColor: sender?.avatar_color || '#8b5cf6',
    to,
    content: content || '',
    msgType: msgType || 'text',
    fileId: fileId || null,
    fileName: fileName || null,
    fileSize: fileSize || null,
    replyTo: replyTo || null,
    timestamp,
  }

  // Push to recipient (all their devices)
  const delivered = pushToUser(to, pushMsg)
  const status = delivered ? 'delivered' : 'stored'
  db.setMessageStatus(mid, to, delivered ? 'delivered' : 'sent')

  // Also push to sender's other devices (multi-device sync)
  pushToUser(fromUserId, { ...pushMsg, _echo: true, _senderDeviceId: senderDeviceId }, true)

  try { db.insertAnalytics('message_send', fromUserId) } catch {}
  return { ok: true, messageId: mid, status, timestamp }
}

/**
 * Handle a group message.
 * @param {string} fromUserId
 * @param {object} msg - { groupId, content, msgType, messageId, fileId, fileName, fileSize, replyTo }
 * @param {function} pushToUser
 * @returns {{ ok, messageId, status }}
 */
function handleGroupMessage(fromUserId, msg, pushToUser, senderDeviceId) {
  const { groupId, content, msgType, messageId, fileId, fileName, fileSize, replyTo, agentId, agentName } = msg
  if (!groupId || (!content && !fileId)) return { ok: false, error: 'MISSING_FIELDS' }

  // Verify membership
  const member = db.getGroupMember(groupId, fromUserId)
  if (!member || member.banned) return { ok: false, error: 'NOT_MEMBER' }
  if (member.is_muted) return { ok: false, error: 'MUTED' }

  const mid = messageId || uuidv4()
  const timestamp = Date.now()

  // Store
  db.insertMessage(mid, fromUserId, null, groupId, content || '', msgType || 'text', fileId, fileName, fileSize, replyTo, agentId)

  // Get sender info + members
  const sender = db.getUserById(fromUserId)
  const members = db.getGroupMembers(groupId)

  const pushMsg = {
    type: 'group_message',
    messageId: mid,
    from: fromUserId,
    fromName: agentName || sender?.display_name || '',
    fromColor: sender?.avatar_color || '#8b5cf6',
    groupId,
    content: content || '',
    msgType: msgType || 'text',
    fileId: fileId || null,
    fileName: fileName || null,
    fileSize: fileSize || null,
    replyTo: replyTo || null,
    agentId: agentId || null,
    agentName: agentName || null,
    timestamp,
  }

  let delivered = 0
  for (const m of members) {
    if (m.user_id === fromUserId) continue
    if (pushToUser(m.user_id, pushMsg)) delivered++
  }

  // Echo to sender's other devices
  pushToUser(fromUserId, { ...pushMsg, _echo: true, _senderDeviceId: senderDeviceId }, true)

  return { ok: true, messageId: mid, status: delivered > 0 ? 'delivered' : 'stored', timestamp, deliveredCount: delivered }
}

/**
 * Sync messages for a user since a given timestamp.
 * Returns DMs + group messages the user should have.
 */
function syncMessages(userId, sinceTimestamp, limit) {
  const since = sinceTimestamp || 0
  const lim = Math.min(limit || 500, 500)

  // Get DMs
  const dms = db.getMessagesForUser(userId, since, lim)

  // Get group messages
  const groups = db.getUserGroups(userId)
  let groupMsgs = []
  for (const g of groups) {
    const msgs = db.getGroupMessages(g.group_id, since, lim)
    groupMsgs = groupMsgs.concat(msgs)
  }

  // Merge and sort by timestamp, limit total
  const all = [...dms, ...groupMsgs].sort((a, b) => a.timestamp - b.timestamp).slice(0, lim)
  return all
}

/**
 * Handle read receipt.
 */
function handleReadReceipt(fromUserId, msg, pushToUser) {
  const { messageIds } = msg
  if (!Array.isArray(messageIds)) return

  for (const mid of messageIds) {
    db.setMessageStatus(mid, fromUserId, 'read')
  }

  // Notify the original sender that messages were read
  // (We'd need to look up each message's sender — simplified version)
  // For now, just acknowledge
  return { ok: true }
}

module.exports = { handleDirectMessage, handleGroupMessage, syncMessages, handleReadReceipt }
