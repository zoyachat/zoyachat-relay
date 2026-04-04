/**
 * WebSocket handler — connection lifecycle, auth, heartbeat, message routing.
 *
 * Connection flow:
 *   1. Client connects → server sends { type: 'hello' }
 *   2. Client sends { type: 'auth', token: '...' }
 *   3. Server verifies JWT → sends { type: 'auth_ok', userId }
 *   4. Bidirectional messaging begins
 */
const auth = require('./auth')
const messageHandler = require('./message-handler')
const groupHandler = require('./group-handler')
const friendHandler = require('./friend-handler')
const presence = require('./presence')
const db = require('./db')
const config = require('./config')

// userId → Set<ws>  (one user can have multiple devices)
const connections = new Map()

/**
 * Initialize WebSocket handling on a WebSocket.Server instance.
 */
function init(wss) {
  wss.on('connection', (ws) => {
    // Enforce global connection limit
    if (wss.clients.size >= config.MAX_CONNECTIONS) {
      ws.send(JSON.stringify({ type: 'error', error: 'SERVER_FULL' }))
      ws.close()
      return
    }

    ws._userId = null
    ws._deviceId = null
    ws._token = null
    ws._alive = true

    ws.send(JSON.stringify({ type: 'hello', timestamp: Date.now() }))

    // Auth timeout — must authenticate within 10 seconds
    const authTimer = setTimeout(() => {
      if (!ws._userId) {
        ws.send(JSON.stringify({ type: 'auth_fail', error: 'AUTH_TIMEOUT' }))
        ws.close()
      }
    }, 10000)

    ws.on('pong', () => { ws._alive = true })

    ws.on('message', (raw) => {
      let msg
      try { msg = JSON.parse(raw) } catch { return }

      if (!ws._userId) {
        // Not yet authenticated — only accept auth messages
        if (msg.type === 'auth') {
          handleAuth(ws, msg, authTimer)
        }
        return
      }

      // Authenticated — route message
      routeMessage(ws, msg)
    })

    ws.on('close', () => {
      clearTimeout(authTimer)
      if (ws._userId) {
        removeConnection(ws)
        // If no more connections for this user, set offline
        if (!hasConnections(ws._userId)) {
          presence.setOffline(ws._userId, pushToUser)
          try { db.insertAnalytics('ws_disconnect', ws._userId) } catch {}
        }
      }
    })

    ws.on('error', () => {}) // prevent crash on ws errors
  })

  // Heartbeat interval
  setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws._alive) { ws.terminate(); return }
      ws._alive = false
      ws.ping()
    })
  }, config.PING_INTERVAL)
}

function handleAuth(ws, msg, authTimer) {
  const { token } = msg
  if (!token) {
    ws.send(JSON.stringify({ type: 'auth_fail', error: 'MISSING_TOKEN' }))
    return
  }

  const result = auth.verifyToken(token)
  if (!result) {
    ws.send(JSON.stringify({ type: 'auth_fail', error: 'INVALID_TOKEN' }))
    ws.close()
    return
  }

  clearTimeout(authTimer)
  ws._userId = result.userId
  ws._deviceId = result.deviceId
  ws._token = token

  // Enforce per-user device limit
  const existingConns = connections.get(result.userId)
  if (existingConns && existingConns.size >= config.MAX_CONNECTIONS_PER_USER) {
    // Close oldest connection
    const oldest = existingConns.values().next().value
    if (oldest) {
      oldest.send(JSON.stringify({ type: 'error', error: 'REPLACED_BY_NEW_DEVICE' }))
      oldest.close()
      existingConns.delete(oldest)
    }
  }

  addConnection(ws)
  presence.setOnline(result.userId, pushToUser)
  try { db.insertAnalytics('ws_connect', result.userId) } catch {}

  const user = db.getUserById(result.userId)
  ws.send(JSON.stringify({
    type: 'auth_ok',
    userId: result.userId,
    displayName: user?.display_name || '',
    avatarColor: user?.avatar_color || '#8b5cf6',
  }))

  // Push pending friend requests count
  const reqCount = friendHandler.friendRequestCount(result.userId)
  if (reqCount > 0) {
    ws.send(JSON.stringify({ type: 'pending_friend_requests', count: reqCount }))
  }
}

function routeMessage(ws, msg) {
  const userId = ws._userId
  // Echo _reqId from client for request-response correlation
  const reqId = msg._reqId
  const reply = (data) => ws.send(JSON.stringify(reqId ? { ...data, _reqId: reqId } : data))

  switch (msg.type) {
    // ── Messages ──
    case 'message': {
      const result = messageHandler.handleDirectMessage(userId, msg, pushToUser, ws._deviceId)
      reply({ type: 'send_ok', ...result })
      break
    }
    case 'group_message': {
      const result = messageHandler.handleGroupMessage(userId, msg, pushToUser, ws._deviceId)
      reply({ type: 'send_ok', ...result })
      break
    }
    case 'read_receipt': {
      messageHandler.handleReadReceipt(userId, msg, pushToUser)
      break
    }
    case 'sync_messages': {
      const messages = messageHandler.syncMessages(userId, msg.since, msg.limit)
      reply({ type: 'sync_result', messages })
      break
    }

    // ── Groups ──
    case 'create_group': {
      const result = groupHandler.createGroup(userId, msg, pushToUser)
      reply({ type: 'group_created', ...result })
      break
    }
    case 'group_invite': {
      const result = groupHandler.inviteMembers(msg.groupId, userId, msg.targetUserIds, pushToUser)
      reply({ type: 'group_invite_result', ...result })
      break
    }
    case 'group_remove_member': {
      const result = groupHandler.removeMember(msg.groupId, userId, msg.targetUserId, pushToUser)
      reply({ type: 'group_remove_result', ...result })
      break
    }
    case 'group_leave': {
      const result = groupHandler.leaveGroup(msg.groupId, userId, pushToUser)
      reply({ type: 'group_leave_result', ...result })
      break
    }
    case 'group_dissolve': {
      const result = groupHandler.dissolveGroup(msg.groupId, userId, pushToUser)
      reply({ type: 'group_dissolve_result', ...result })
      break
    }
    case 'group_info': {
      const info = groupHandler.getGroupInfo(msg.groupId, userId)
      reply({ type: 'group_info_result', ...info })
      break
    }
    case 'group_update': {
      const result = groupHandler.updateGroupInfo(msg.groupId, userId, msg)
      reply({ type: 'group_update_result', ...result })
      break
    }

    // ── Friends ──
    case 'friend_request': {
      const result = friendHandler.sendFriendRequest(userId, msg.toUserId, msg.message, pushToUser)
      reply({ type: 'friend_request_result', ...result })
      break
    }
    case 'friend_accept': {
      const result = friendHandler.acceptFriendRequest(msg.requestId, userId, pushToUser)
      reply({ type: 'friend_accept_result', ...result })
      break
    }
    case 'friend_reject': {
      const result = friendHandler.rejectFriendRequest(msg.requestId, userId)
      reply({ type: 'friend_reject_result', ...result })
      break
    }
    case 'friend_list': {
      const requests = friendHandler.listFriendRequests(userId)
      reply({ type: 'friend_list_result', requests })
      break
    }
    case 'search_users': {
      const users = friendHandler.searchUsers(msg.query)
      reply({ type: 'search_result', users })
      break
    }

    // ── Contacts ──
    case 'contacts_list': {
      const contacts = db.getContacts(userId)
      reply({ type: 'contacts_list_result', contacts })
      break
    }
    case 'contact_update': {
      db.updateContact(userId, msg.contactId, { remark_name: msg.remarkName })
      reply({ type: 'contact_update_result', ok: true })
      break
    }
    case 'contact_delete': {
      db.deleteContact(userId, msg.contactId)
      db.deleteContact(msg.contactId, userId) // bidirectional
      reply({ type: 'contact_delete_result', ok: true })
      break
    }

    // ── Presence ──
    case 'get_presence': {
      const presences = presence.getPresence(msg.userIds || [])
      reply({ type: 'presence_result', presences })
      break
    }

    // ── Profile ──
    case 'get_profile': {
      const user = db.getUserById(msg.userId || userId)
      if (user) {
        reply({ type: 'profile_result', user: { userId: user.user_id, username: user.username, displayName: user.display_name, avatarColor: user.avatar_color, avatarImage: user.avatar_image, bio: user.bio } })
      }
      break
    }
    case 'update_profile': {
      db.updateUserProfile(userId, msg)
      reply({ type: 'profile_updated', ok: true })
      break
    }

    // ── Pin message ──
    case 'pin_message': {
      const { groupId: pinGroupId, messageId: pinMsgId } = msg
      if (pinGroupId) {
        db.updateGroup(pinGroupId, { pinned_message: pinMsgId || '' })
        const members = db.getGroupMembers(pinGroupId)
        for (const m of members) {
          if (m.user_id !== userId) pushToUser(m.user_id, { type: 'pin_message', groupId: pinGroupId, messageId: pinMsgId, from: userId })
        }
      }
      reply({ type: 'pin_ok', ok: true })
      break
    }

    // ── Groups list ──
    case 'groups_list': {
      const groups = db.getUserGroups(userId)
      reply({ type: 'groups_list_result', groups })
      break
    }

    // ── Devices ──
    case 'devices_list': {
      const devices = db.getUserDevices(userId)
      reply({ type: 'devices_list_result', devices })
      break
    }

    // ── Typing indicator ──
    case 'typing': {
      const { to, groupId } = msg
      if (groupId) {
        const members = db.getGroupMembers(groupId)
        for (const m of members) {
          if (m.user_id !== userId) pushToUser(m.user_id, { type: 'typing', from: userId, groupId })
        }
      } else if (to) {
        pushToUser(to, { type: 'typing', from: userId })
      }
      break
    }

    default:
      reply({ type: 'error', error: 'UNKNOWN_TYPE', detail: msg.type })
  }
}

// ── Connection management ──────────────────────────────────────

function addConnection(ws) {
  if (!connections.has(ws._userId)) connections.set(ws._userId, new Set())
  connections.get(ws._userId).add(ws)
}

function removeConnection(ws) {
  const set = connections.get(ws._userId)
  if (set) {
    set.delete(ws)
    if (set.size === 0) connections.delete(ws._userId)
  }
}

function hasConnections(userId) {
  return connections.has(userId) && connections.get(userId).size > 0
}

/**
 * Push a message to all connected devices of a user.
 * @param {string} userId
 * @param {object} msg
 * @param {boolean} excludeSender - if true, skip the ws that matches msg's origin
 * @returns {boolean} - true if at least one device received it
 */
function pushToUser(userId, msg, excludeSender) {
  const set = connections.get(userId)
  if (!set || set.size === 0) return false

  const data = JSON.stringify(msg)
  let delivered = false
  for (const ws of set) {
    try {
      // For _echo messages, skip the device that sent the original
      if (excludeSender && msg._echo && ws._deviceId === msg._senderDeviceId) continue
      ws.send(data)
      delivered = true
    } catch {}
  }
  return delivered
}

function getOnlineUserCount() {
  return connections.size
}

module.exports = { init, pushToUser, getOnlineUserCount }
