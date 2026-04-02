/**
 * Standalone ZoyaChat Relay Server (for VPS deployment)
 *
 * This is the same relay logic as electron/relay/server.js but
 * packaged as a standalone Node.js server with its own deps.
 *
 * Usage: node relay-ws.mjs
 * Port: 9090 (env: PORT)
 * DB: ./data/relay.db
 * Max connections: 100 (env: MAX_CONNECTIONS)
 */

import { WebSocketServer } from 'ws'
import Database from 'better-sqlite3'
import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import http from 'http'

const PORT = parseInt(process.env.PORT || '9090')
const HTTP_PORT = parseInt(process.env.HTTP_PORT || '9091')
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS || '100')
const AUTH_TIMEOUT_MS = 10000
const PING_INTERVAL_MS = 30000
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000

// ── Base58 ──────────────────────────────────────────────────────
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58Decode(str) {
  const bytes = [0]
  for (const char of str) {
    const idx = ALPHABET.indexOf(char)
    if (idx < 0) throw new Error(`Invalid base58 character: ${char}`)
    let carry = idx
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  let numLeadingZeros = 0
  for (const char of str) {
    if (char !== ALPHABET[0]) break
    numLeadingZeros++
  }
  const result = new Uint8Array(numLeadingZeros + bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    result[numLeadingZeros + bytes.length - 1 - i] = bytes[i]
  }
  return result
}

function generateChallenge() {
  return crypto.randomBytes(32).toString('hex')
}

async function verifySignature(peerId, challenge, signature) {
  try {
    const { ed25519 } = await import('@noble/curves/ed25519.js')
    const pubKey = base58Decode(peerId)
    if (pubKey.length !== 32) return false
    const messageBytes = Buffer.from(challenge, 'hex')
    const sigBytes = Buffer.from(signature, 'hex')
    return ed25519.verify(sigBytes, messageBytes, pubKey)
  } catch {
    return false
  }
}

// ── Database ────────────────────────────────────────────────────
fs.mkdirSync('./data', { recursive: true })
const db = new Database('./data/relay.db')
db.pragma('journal_mode = WAL')
db.pragma('synchronous = NORMAL')

db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE NOT NULL,
    from_peer TEXT NOT NULL,
    to_peer TEXT NOT NULL,
    payload TEXT NOT NULL,
    group_id TEXT,
    timestamp INTEGER NOT NULL,
    delivered INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_peer, delivered);

  CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    admin_peer TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    PRIMARY KEY (group_id, peer_id)
  );

  CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL,
    used_by TEXT,
    used_at INTEGER
  );
`)

// Delegates table (linked device message delegation)
db.exec(`
  CREATE TABLE IF NOT EXISTS delegates (
    origin_peer TEXT NOT NULL,
    delegate_peer TEXT NOT NULL,
    registered_at INTEGER DEFAULT (unixepoch()),
    PRIMARY KEY (origin_peer, delegate_peer)
  );
  CREATE INDEX IF NOT EXISTS idx_delegates_origin ON delegates(origin_peer);
  CREATE INDEX IF NOT EXISTS idx_delegates_delegate ON delegates(delegate_peer);
`)
try { db.exec('ALTER TABLE messages ADD COLUMN delegated_for TEXT') } catch {}

console.log('[relay] Database ready')

// ── State ───────────────────────────────────────────────────────
const clients = new Map()      // peerId → { ws, authedAt }
const pendingAuth = new Map()  // ws → { challenge, timer }

// ── WebSocket Server ────────────────────────────────────────────
const wss = new WebSocketServer({ port: PORT })

wss.on('connection', (ws) => {
  if (MAX_CONNECTIONS > 0 && clients.size >= MAX_CONNECTIONS) {
    ws.send(JSON.stringify({ type: 'error', error: 'RELAY_FULL' }))
    ws.close()
    return
  }

  const challenge = generateChallenge()
  pendingAuth.set(ws, {
    challenge,
    timer: setTimeout(() => {
      if (pendingAuth.has(ws)) {
        ws.send(JSON.stringify({ type: 'auth_fail', error: 'AUTH_TIMEOUT' }))
        ws.close()
        pendingAuth.delete(ws)
      }
    }, AUTH_TIMEOUT_MS),
  })

  ws.send(JSON.stringify({ type: 'challenge', challenge }))

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString())
      handleMessage(ws, msg)
    } catch {
      ws.send(JSON.stringify({ type: 'error', error: 'INVALID_JSON' }))
    }
  })

  ws.on('close', () => {
    for (const [peerId, client] of clients) {
      if (client.ws === ws) {
        clients.delete(peerId)
        console.log(`[relay] Disconnected: ${peerId.slice(0, 16)}... (${clients.size} online)`)
        break
      }
    }
    const p = pendingAuth.get(ws)
    if (p) { clearTimeout(p.timer); pendingAuth.delete(ws) }
  })

  ws.on('error', () => {})
})

// ── Message handling ────────────────────────────────────────────

async function handleMessage(ws, msg) {
  if (msg.type === 'auth') {
    await handleAuth(ws, msg)
    return
  }

  const peerId = getPeerId(ws)
  if (!peerId) {
    ws.send(JSON.stringify({ type: 'auth_fail', error: 'NOT_AUTHENTICATED' }))
    return
  }

  // Diagnostic: log messages with missing or non-string messageId
  if (msg.type === 'message' || msg.type === 'group_message') {
    if (msg.messageId === undefined || msg.messageId === null) {
      console.warn(`[relay] WARN: ${msg.type} from ${peerId.slice(0, 12)} missing messageId, keys: ${Object.keys(msg).join(',')}`)
    } else if (typeof msg.messageId !== 'string') {
      console.warn(`[relay] WARN: ${msg.type} from ${peerId.slice(0, 12)} messageId type=${typeof msg.messageId} value=${msg.messageId}`)
    }
  }

  switch (msg.type) {
    case 'message': handleDirectMessage(peerId, msg); break
    case 'group_message': handleGroupMessage(peerId, msg); break
    case 'receipt': handleReceipt(peerId, msg); break
    case 'file_chunk': {
      const effFrom = resolveDelegatePeer(peerId)
      const { to, fileId, chunkIndex, data, totalChunks, fileName } = msg
      pushToClient(to, { type: 'file_chunk', from: effFrom, fileId, chunkIndex, data, totalChunks, fileName })
      const fcDels = getDelegatesOf(to)
      for (const d of fcDels) pushToClient(d, { type: 'file_chunk', from: effFrom, fileId, chunkIndex, data, totalChunks, fileName, delegatedFor: to })
      break
    }
    case 'file_request': {
      const effFrom = resolveDelegatePeer(peerId)
      pushToClient(msg.to, { type: 'file_request', from: effFrom, fileId: msg.fileId })
      const frqDels = getDelegatesOf(msg.to)
      for (const d of frqDels) pushToClient(d, { type: 'file_request', from: effFrom, fileId: msg.fileId, delegatedFor: msg.to })
      break
    }
    case 'agent_message': {
      const effFrom = resolveDelegatePeer(peerId)
      if (!msg.to) { ws.send(JSON.stringify({ type: 'error', error: 'MISSING_FIELDS' })); break }
      if (!pushToClient(msg.to, { ...msg, from: effFrom })) {
        ws.send(JSON.stringify({ type: 'error', error: 'HOST_OFFLINE', agentId: msg.agentId }))
      }
      break
    }
    case 'agent_stream':
    case 'agent_stream_end':
    case 'error':
      if (msg.to) pushToClient(msg.to, { ...msg, from: resolveDelegatePeer(peerId) })
      break
    case 'friend_request': handleFriendRequest(peerId, msg); break
    case 'register_delegate': {
      const { delegatePeerId } = msg
      if (!delegatePeerId || delegatePeerId === peerId) { sendTo(peerId, { type: 'error', error: 'MISSING_FIELDS' }); break }
      db.prepare('INSERT OR REPLACE INTO delegates (origin_peer, delegate_peer) VALUES (?, ?)').run(peerId, delegatePeerId)
      sendTo(peerId, { type: 'delegate_registered', delegatePeerId })
      pushDelegatedPending(peerId, delegatePeerId)
      console.log(`[relay] Delegate registered: ${delegatePeerId.slice(0, 12)} for origin ${peerId.slice(0, 12)}`)
      break
    }
    case 'unregister_delegate': {
      const { delegatePeerId: delP } = msg
      if (!delP) break
      db.prepare('DELETE FROM delegates WHERE origin_peer = ? AND delegate_peer = ?').run(peerId, delP)
      sendTo(peerId, { type: 'delegate_unregistered', delegatePeerId: delP })
      console.log(`[relay] Delegate unregistered: ${delP.slice(0, 12)} from origin ${peerId.slice(0, 12)}`)
      break
    }
    case 'unregister_self_delegate': {
      db.prepare('DELETE FROM delegates WHERE delegate_peer = ?').run(peerId)
      sendTo(peerId, { type: 'self_delegate_unregistered' })
      console.log(`[relay] Self-unregistered delegate: ${peerId.slice(0, 12)}`)
      break
    }
    case 'ack': handleAck(peerId, msg); break
    default:
      ws.send(JSON.stringify({ type: 'error', error: 'UNKNOWN_TYPE' }))
  }
}

async function handleAuth(ws, msg) {
  const pending = pendingAuth.get(ws)
  if (!pending) { ws.send(JSON.stringify({ type: 'auth_fail', error: 'NO_CHALLENGE' })); return }

  const { peerId, signature } = msg
  if (!peerId || !signature) { ws.send(JSON.stringify({ type: 'auth_fail', error: 'MISSING_FIELDS' })); return }

  const valid = await verifySignature(peerId, pending.challenge, signature)
  if (!valid) {
    ws.send(JSON.stringify({ type: 'auth_fail', error: 'INVALID_SIGNATURE' }))
    ws.close()
    clearTimeout(pending.timer)
    pendingAuth.delete(ws)
    return
  }

  // Close existing connection for this peer
  const existing = clients.get(peerId)
  if (existing && existing.ws !== ws) {
    try { existing.ws.close() } catch {}
  }

  clearTimeout(pending.timer)
  pendingAuth.delete(ws)
  clients.set(peerId, { ws, authedAt: Date.now() })

  ws.send(JSON.stringify({ type: 'auth_ok', peerId }))
  console.log(`[relay] Authenticated: ${peerId.slice(0, 16)}... (${clients.size} online)`)

  // Push pending messages
  pushPendingMessages(peerId)
}

function handleDirectMessage(fromPeer, msg) {
  const { to, payload, timestamp } = msg
  const messageId = typeof msg.messageId === 'string' ? msg.messageId : (msg.messageId != null ? String(msg.messageId) : null)
  if (!to || !payload || !messageId) { sendTo(fromPeer, { type: 'error', error: 'MISSING_FIELDS' }); return }

  const effectiveFrom = resolveDelegatePeer(fromPeer)
  const payloadStr = (payload && typeof payload === 'object') ? JSON.stringify(payload) : payload
  const ts = timestamp || Date.now()

  db.prepare(`INSERT OR IGNORE INTO messages (message_id, from_peer, to_peer, payload, timestamp) VALUES (?, ?, ?, ?, ?)`)
    .run(messageId, effectiveFrom, to, payloadStr, ts)

  const delivered = pushToClient(to, { type: 'message', from: effectiveFrom, payload, messageId, timestamp: ts })

  if (delivered) {
    db.prepare(`UPDATE messages SET delivered = 1 WHERE message_id = ? AND to_peer = ?`).run(messageId, to)
    sendTo(fromPeer, { type: 'send_ok', messageId, status: 'delivered' })
    pushToDelegates(to, { type: 'message', from: effectiveFrom, payload, messageId, timestamp: ts }, payloadStr, messageId)
    console.log(`[relay] DELIVERED ${messageId.slice(0, 12)}... ${effectiveFrom.slice(0, 12)} → ${to.slice(0, 12)}`)
  } else {
    sendTo(fromPeer, { type: 'send_ok', messageId, status: 'stored' })
    pushToDelegates(to, { type: 'message', from: effectiveFrom, payload, messageId, timestamp: ts }, payloadStr, messageId)
    console.log(`[relay] STORED ${messageId.slice(0, 12)}... for ${to.slice(0, 12)}`)
  }
}

function handleGroupMessage(fromPeer, msg) {
  const { groupId, payload } = msg
  const messageId = typeof msg.messageId === 'string' ? msg.messageId : (msg.messageId != null ? String(msg.messageId) : null)
  if (!groupId || !payload || !messageId) return

  const effectiveFrom = resolveDelegatePeer(fromPeer)
  const payloadStr = (payload && typeof payload === 'object') ? JSON.stringify(payload) : payload
  const ts = Date.now()

  const members = db.prepare(`SELECT peer_id FROM group_members WHERE group_id = ?`).all(groupId).map(r => r.peer_id)
  if (!members.includes(effectiveFrom)) { sendTo(fromPeer, { type: 'error', error: 'NOT_MEMBER' }); return }

  // Pre-fetch delegates for all members (avoid per-member DB queries)
  const memberDels = new Map()
  for (const m of members) {
    if (m === effectiveFrom) continue
    const dels = getDelegatesOf(m)
    if (dels.length) memberDels.set(m, dels)
  }

  let delivered = 0, stored = 0
  for (const member of members) {
    if (member === effectiveFrom) continue
    const mid = `${messageId}_${member.slice(0, 8)}`
    db.prepare(`INSERT OR IGNORE INTO messages (message_id, from_peer, to_peer, payload, group_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(mid, effectiveFrom, member, payloadStr, groupId, ts)

    if (pushToClient(member, { type: 'group_message', from: effectiveFrom, groupId, payload, messageId, timestamp: ts })) {
      db.prepare(`UPDATE messages SET delivered = 1 WHERE message_id = ?`).run(mid)
      delivered++
    } else {
      stored++
    }

    // Push to member's delegates
    const dels = memberDels.get(member)
    if (dels) {
      for (const delPeer of dels) {
        const delMid = `${mid}_del_${delPeer.slice(0, 8)}`
        const delegatedMsg = { type: 'group_message', from: effectiveFrom, groupId, payload, messageId, timestamp: ts, delegatedFor: member }
        const dOk = pushToClient(delPeer, delegatedMsg)
        db.prepare('INSERT OR IGNORE INTO messages (message_id,from_peer,to_peer,payload,group_id,timestamp,delivered,delegated_for) VALUES (?,?,?,?,?,?,?,?)')
          .run(delMid, effectiveFrom, delPeer, payloadStr, groupId, ts, dOk ? 1 : 0, member)
      }
    }
  }

  sendTo(fromPeer, { type: 'send_ok', messageId, status: delivered > 0 ? 'delivered' : 'stored', delivered, stored })
}

function handleReceipt(fromPeer, msg) {
  const { to, messageId, receiptType } = msg
  if (!to || !messageId) return
  const effectiveFrom = resolveDelegatePeer(fromPeer)
  pushToClient(to, { type: 'receipt', from: effectiveFrom, messageId, receiptType: receiptType || 'delivered' })
  // Push receipt to delegates of recipient
  for (const d of getDelegatesOf(to)) {
    pushToClient(d, { type: 'receipt', from: effectiveFrom, messageId, receiptType: receiptType || 'delivered', delegatedFor: to })
  }
}

function handleFriendRequest(fromPeer, msg) {
  const { to, displayName } = msg
  if (!to) return
  const effectiveFrom = resolveDelegatePeer(fromPeer)
  pushToClient(to, { type: 'friend_request', from: effectiveFrom, displayName: displayName || effectiveFrom.slice(0, 12) })
  // Push to delegates of recipient
  for (const d of getDelegatesOf(to)) {
    pushToClient(d, { type: 'friend_request', from: effectiveFrom, displayName: displayName || effectiveFrom.slice(0, 12), delegatedFor: to })
  }
  sendTo(fromPeer, { type: 'send_ok', status: 'sent' })
}

function handleAck(peerId, msg) {
  const { messageIds } = msg
  if (!Array.isArray(messageIds)) return
  const effectivePeerId = resolveDelegatePeer(peerId)
  const stmt = db.prepare(`UPDATE messages SET delivered = 1 WHERE message_id = ? AND to_peer = ?`)
  for (const id of messageIds) {
    stmt.run(id, effectivePeerId)
    // Also mark delegate copies
    if (effectivePeerId !== peerId) {
      stmt.run(id + '_del_' + peerId.slice(0, 8), peerId)
    }
  }
}

// ── Push helpers ────────────────────────────────────────────────

function pushToClient(peerId, msg) {
  const client = clients.get(peerId)
  if (!client || client.ws.readyState !== 1) return false
  try { client.ws.send(JSON.stringify(msg)); return true } catch { return false }
}

function sendTo(peerId, msg) { pushToClient(peerId, msg) }

function pushPendingMessages(peerId) {
  // Step 1: Push own pending messages (non-delegated)
  const rows = db.prepare(`SELECT * FROM messages WHERE to_peer = ? AND delivered = 0 AND delegated_for IS NULL ORDER BY timestamp ASC LIMIT 100`).all(peerId)
  if (rows.length > 0) {
    console.log(`[relay] Pushing ${rows.length} pending message(s) to ${peerId.slice(0, 16)}...`)
    for (const row of rows) {
      let parsedPayload = row.payload
      try { if (typeof parsedPayload === 'string') parsedPayload = JSON.parse(parsedPayload) } catch {}
      const payload = row.group_id
        ? { type: 'group_message', from: row.from_peer, groupId: row.group_id, payload: parsedPayload, messageId: row.message_id, timestamp: row.timestamp }
        : { type: 'message', from: row.from_peer, payload: parsedPayload, messageId: row.message_id, timestamp: row.timestamp }
      if (pushToClient(peerId, payload)) {
        db.prepare(`UPDATE messages SET delivered = 1 WHERE message_id = ?`).run(row.message_id)
      } else break
    }
  }

  // Step 2: Push delegated pending (messages stored for this peer as a delegate)
  const delRows = db.prepare(`SELECT * FROM messages WHERE to_peer = ? AND delivered = 0 AND delegated_for IS NOT NULL ORDER BY timestamp ASC LIMIT 100`).all(peerId)
  for (const row of delRows) {
    let p = row.payload
    try { if (typeof p === 'string') p = JSON.parse(p) } catch {}
    const msg = row.group_id
      ? { type: 'group_message', from: row.from_peer, groupId: row.group_id, payload: p, messageId: row.message_id, timestamp: row.timestamp, delegatedFor: row.delegated_for }
      : { type: 'message', from: row.from_peer, payload: p, messageId: row.message_id, timestamp: row.timestamp, delegatedFor: row.delegated_for }
    if (pushToClient(peerId, msg)) {
      db.prepare(`UPDATE messages SET delivered = 1 WHERE message_id = ?`).run(row.message_id)
    } else break
  }

  // Step 3: As a delegate, push origin's pending messages
  const delegations = db.prepare('SELECT origin_peer FROM delegates WHERE delegate_peer = ?').all(peerId)
  for (const del of delegations) {
    pushDelegatedPending(del.origin_peer, peerId)
  }
}

function getPeerId(ws) {
  for (const [peerId, client] of clients) {
    if (client.ws === ws) return peerId
  }
  return null
}

// ── Delegate helpers ────────────────────────────────────────────

function resolveDelegatePeer(fromPeer) {
  const row = db.prepare('SELECT origin_peer FROM delegates WHERE delegate_peer = ?').get(fromPeer)
  return row ? row.origin_peer : fromPeer
}

function getDelegatesOf(originPeer) {
  return db.prepare('SELECT delegate_peer FROM delegates WHERE origin_peer = ?')
    .all(originPeer).map(r => r.delegate_peer)
}

function pushToDelegates(originPeer, pushMsg, payloadStr, messageId) {
  const delegates = getDelegatesOf(originPeer)
  for (const del of delegates) {
    const delMid = `${messageId}_del_${del.slice(0, 8)}`
    const delegatedMsg = { ...pushMsg, delegatedFor: originPeer }
    const delivered = pushToClient(del, delegatedMsg)
    db.prepare(
      'INSERT OR IGNORE INTO messages (message_id,from_peer,to_peer,payload,group_id,timestamp,delivered,delegated_for) VALUES (?,?,?,?,?,?,?,?)'
    ).run(delMid, pushMsg.from, del, payloadStr, pushMsg.groupId || null, pushMsg.timestamp || Date.now(), delivered ? 1 : 0, originPeer)
  }
}

function pushDelegatedPending(originPeer, delegatePeer) {
  const client = clients.get(delegatePeer)
  if (!client || client.ws.readyState !== 1) return
  const rows = db.prepare(
    'SELECT * FROM messages WHERE to_peer = ? AND delivered = 0 AND delegated_for IS NULL ORDER BY timestamp ASC LIMIT 100'
  ).all(originPeer)
  if (!rows.length) return
  console.log(`[relay] Pushing ${rows.length} delegated pending to ${delegatePeer.slice(0, 12)} for origin ${originPeer.slice(0, 12)}`)
  for (const row of rows) {
    const delMid = `${row.message_id}_del_${delegatePeer.slice(0, 8)}`
    const exists = db.prepare('SELECT 1 FROM messages WHERE message_id = ?').get(delMid)
    if (exists) continue
    let p = row.payload
    try { if (typeof p === 'string') p = JSON.parse(p) } catch {}
    const msg = row.group_id
      ? { type: 'group_message', from: row.from_peer, groupId: row.group_id, payload: p, messageId: row.message_id, timestamp: row.timestamp, delegatedFor: originPeer }
      : { type: 'message', from: row.from_peer, payload: p, messageId: row.message_id, timestamp: row.timestamp, delegatedFor: originPeer }
    const ok = pushToClient(delegatePeer, msg)
    db.prepare(
      'INSERT OR IGNORE INTO messages (message_id,from_peer,to_peer,payload,group_id,timestamp,delivered,delegated_for) VALUES (?,?,?,?,?,?,?,?)'
    ).run(delMid, row.from_peer, delegatePeer, row.payload, row.group_id || null, row.timestamp, ok ? 1 : 0, originPeer)
  }
}

// ── Ping & Cleanup ──────────────────────────────────────────────

setInterval(() => {
  for (const [peerId, client] of clients) {
    if (client.ws.readyState !== 1) { clients.delete(peerId); continue }
    client.ws.ping()
  }
}, PING_INTERVAL_MS)

setInterval(() => {
  const cutoff = Math.floor((Date.now() - 7 * 24 * 60 * 60 * 1000) / 1000)
  const result = db.prepare(`DELETE FROM messages WHERE created_at < ?`).run(cutoff)
  if (result.changes > 0) console.log(`[relay] Cleaned ${result.changes} expired messages`)
  // Clean stale delegates (not seen for 30 days)
  const delCutoff = Math.floor((Date.now() - 30 * 24 * 60 * 60 * 1000) / 1000)
  const delResult = db.prepare('DELETE FROM delegates WHERE registered_at < ?').run(delCutoff)
  if (delResult.changes > 0) console.log(`[relay] Cleaned ${delResult.changes} stale delegates`)
}, CLEANUP_INTERVAL_MS)

// ── HTTP health check ───────────────────────────────────────────

// Backup data tables
db.exec(`
  CREATE TABLE IF NOT EXISTS backups (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
  );
`)

const BACKUP_TTL = 7 * 24 * 60 * 60  // 7 days in seconds
const MAX_BACKUP_SIZE = 50 * 1024 * 1024  // 50MB

http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)

  if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ status: 'ok', connections: clients.size, uptime: process.uptime() }))

  } else if (req.method === 'POST' && url.pathname === '/backup/store') {
    let body = ''
    req.on('data', chunk => {
      body += chunk
      if (Buffer.byteLength(body) > MAX_BACKUP_SIZE) {
        res.writeHead(413, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'too_large' }))
        req.destroy()
      }
    })
    req.on('end', () => {
      try {
        const { key, data } = JSON.parse(body)
        if (!key || !data) { res.writeHead(400); res.end(JSON.stringify({ error: 'Missing key or data' })); return }
        const expiresAt = Math.floor(Date.now() / 1000) + BACKUP_TTL
        db.prepare(`INSERT OR REPLACE INTO backups (key, data, expires_at) VALUES (?, ?, ?)`).run(key, JSON.stringify(data), expiresAt)
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, expiresAt: expiresAt * 1000 }))
      } catch {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON' }))
      }
    })

  } else if (req.method === 'GET' && url.pathname.startsWith('/backup/fetch/')) {
    const key = url.pathname.slice('/backup/fetch/'.length)
    if (!key) { res.writeHead(400); res.end(JSON.stringify({ error: 'Missing key' })); return }
    const row = db.prepare(`SELECT * FROM backups WHERE key = ? AND expires_at > ?`).get(key, Math.floor(Date.now() / 1000))
    if (!row) { res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' })); return }
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ data: JSON.parse(row.data) }))

  } else {
    res.writeHead(404)
    res.end('Not found')
  }
}).listen(HTTP_PORT)

// Cleanup expired backups hourly
setInterval(() => {
  db.prepare(`DELETE FROM backups WHERE expires_at < ?`).run(Math.floor(Date.now() / 1000))
}, 60 * 60 * 1000)

console.log(`[relay] ZoyaChat Relay Server`)
console.log(`[relay] WebSocket: ws://0.0.0.0:${PORT}`)
console.log(`[relay] Health: http://0.0.0.0:${HTTP_PORT}/health`)
console.log(`[relay] Max connections: ${MAX_CONNECTIONS}`)
