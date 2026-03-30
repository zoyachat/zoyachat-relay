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
// ── Storage limits (anti-abuse) ─────────────────────────────────
const MAX_PAYLOAD_SIZE = 100 * 1024                // 100 KB per single message
const MAX_STORED_PER_RECIPIENT = 10000             // max offline messages per recipient
const MAX_BYTES_PER_RECIPIENT = 5 * 1024 * 1024    // 5 MB per recipient
const MAX_RECIPIENTS = 1000                        // max distinct offline recipients
const MAX_STORED_FROM_SENDER = 50                  // per sender → per offline recipient
const MAX_GROUP_STORED_PER_MEMBER = 200            // group offline: keep latest 200, FIFO
const MESSAGE_TTL_MS = 72 * 60 * 60 * 1000         // 72 hours

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
    const { ed25519 } = await import('@noble/curves/ed25519')
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

  switch (msg.type) {
    case 'message': handleDirectMessage(peerId, msg); break
    case 'group_message': handleGroupMessage(peerId, msg); break
    case 'receipt': handleReceipt(peerId, msg); break
    case 'file_chunk': pushToClient(msg.to, { type: 'file_chunk', from: peerId, ...msg }); break
    case 'file_request': pushToClient(msg.to, { type: 'file_request', from: peerId, fileId: msg.fileId }); break
    case 'agent_message':
      if (!msg.to) { ws.send(JSON.stringify({ type: 'error', error: 'MISSING_FIELDS' })); break }
      if (!pushToClient(msg.to, { ...msg, from: peerId })) {
        ws.send(JSON.stringify({ type: 'error', error: 'HOST_OFFLINE', agentId: msg.agentId }))
      }
      break
    case 'agent_stream':
      if (msg.to) pushToClient(msg.to, msg)
      break
    case 'agent_stream_end':
      if (msg.to) pushToClient(msg.to, msg)
      break
    case 'error':
      if (msg.to) pushToClient(msg.to, msg)
      break
    case 'friend_request': handleFriendRequest(peerId, msg); break
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
  const { to, payload, messageId, timestamp } = msg
  if (!to || !payload || !messageId) { sendTo(fromPeer, { type: 'error', error: 'MISSING_FIELDS' }); return }

  // Stringify payload if it's an object (encrypted { nonce, ciphertext })
  const payloadStr = (payload && typeof payload === 'object') ? JSON.stringify(payload) : payload

  // Payload size check
  if (typeof payloadStr === 'string' && payloadStr.length > MAX_PAYLOAD_SIZE) {
    sendTo(fromPeer, { type: 'error', error: 'PAYLOAD_TOO_LARGE', messageId })
    return
  }

  const delivered = pushToClient(to, { type: 'message', from: fromPeer, payload, messageId, timestamp: timestamp || Date.now() })

  if (delivered) {
    // Store + mark delivered immediately
    db.prepare(`INSERT OR IGNORE INTO messages (message_id, from_peer, to_peer, payload, timestamp, delivered) VALUES (?, ?, ?, ?, ?, 1)`)
      .run(messageId, fromPeer, to, payloadStr, timestamp || Date.now())
    sendTo(fromPeer, { type: 'send_ok', messageId, status: 'delivered' })
    console.log(`[relay] DELIVERED ${messageId.slice(0, 12)}... ${fromPeer.slice(0, 12)} → ${to.slice(0, 12)}`)
  } else {
    // Offline storage — check limits before storing
    const recipientCount = db.prepare(`SELECT COUNT(DISTINCT to_peer) AS cnt FROM messages WHERE delivered = 0`).get()
    const isNewRecipient = !db.prepare(`SELECT 1 FROM messages WHERE to_peer = ? AND delivered = 0 LIMIT 1`).get(to)
    if (isNewRecipient && (recipientCount?.cnt || 0) >= MAX_RECIPIENTS) {
      sendTo(fromPeer, { type: 'error', error: 'RELAY_FULL', messageId })
      return
    }
    const perRecipient = db.prepare(`SELECT COUNT(*) AS cnt, SUM(LENGTH(payload)) AS bytes FROM messages WHERE to_peer = ? AND delivered = 0`).get(to)
    if ((perRecipient?.cnt || 0) >= MAX_STORED_PER_RECIPIENT) {
      sendTo(fromPeer, { type: 'error', error: 'RECIPIENT_QUOTA_EXCEEDED', messageId })
      return
    }
    if ((perRecipient?.bytes || 0) + payloadStr.length > MAX_BYTES_PER_RECIPIENT) {
      sendTo(fromPeer, { type: 'error', error: 'RECIPIENT_SIZE_EXCEEDED', messageId })
      return
    }
    // Per-sender limit for this offline recipient
    const fromSender = db.prepare(`SELECT COUNT(*) AS cnt FROM messages WHERE from_peer = ? AND to_peer = ? AND delivered = 0`).get(fromPeer, to)
    if ((fromSender?.cnt || 0) >= MAX_STORED_FROM_SENDER) {
      sendTo(fromPeer, { type: 'error', error: 'SENDER_QUOTA_EXCEEDED', messageId })
      return
    }

    db.prepare(`INSERT OR IGNORE INTO messages (message_id, from_peer, to_peer, payload, timestamp) VALUES (?, ?, ?, ?, ?)`)
      .run(messageId, fromPeer, to, payloadStr, timestamp || Date.now())
    sendTo(fromPeer, { type: 'send_ok', messageId, status: 'stored' })
    console.log(`[relay] STORED ${messageId.slice(0, 12)}... for ${to.slice(0, 12)}`)
  }
}

function handleGroupMessage(fromPeer, msg) {
  const { groupId, payload, messageId } = msg
  if (!groupId || !payload || !messageId) return

  const payloadStr = (payload && typeof payload === 'object') ? JSON.stringify(payload) : payload

  if (typeof payloadStr === 'string' && payloadStr.length > MAX_PAYLOAD_SIZE) {
    sendTo(fromPeer, { type: 'error', error: 'PAYLOAD_TOO_LARGE', messageId })
    return
  }

  const members = db.prepare(`SELECT peer_id FROM group_members WHERE group_id = ?`).all(groupId).map(r => r.peer_id)
  if (!members.includes(fromPeer)) { sendTo(fromPeer, { type: 'error', error: 'NOT_MEMBER' }); return }

  let delivered = 0, stored = 0
  for (const member of members) {
    if (member === fromPeer) continue
    const mid = `${messageId}_${member.slice(0, 8)}`

    if (pushToClient(member, { type: 'group_message', from: fromPeer, groupId, payload, messageId, timestamp: Date.now() })) {
      db.prepare(`INSERT OR IGNORE INTO messages (message_id, from_peer, to_peer, payload, group_id, timestamp, delivered) VALUES (?, ?, ?, ?, ?, ?, 1)`)
        .run(mid, fromPeer, member, payloadStr, groupId, Date.now())
      delivered++
    } else {
      // Check per-recipient total quota
      const perRecipient = db.prepare(`SELECT SUM(LENGTH(payload)) AS bytes FROM messages WHERE to_peer = ? AND delivered = 0`).get(member)
      if ((perRecipient?.bytes || 0) + payloadStr.length > MAX_BYTES_PER_RECIPIENT) { stored++; continue }
      // Group FIFO: keep only latest MAX_GROUP_STORED_PER_MEMBER per group per member
      const groupCount = db.prepare(`SELECT COUNT(*) AS cnt FROM messages WHERE to_peer = ? AND group_id = ? AND delivered = 0`).get(member, groupId)
      if ((groupCount?.cnt || 0) >= MAX_GROUP_STORED_PER_MEMBER) {
        db.prepare(`DELETE FROM messages WHERE id = (SELECT id FROM messages WHERE to_peer = ? AND group_id = ? AND delivered = 0 ORDER BY timestamp ASC LIMIT 1)`).run(member, groupId)
      }
      db.prepare(`INSERT OR IGNORE INTO messages (message_id, from_peer, to_peer, payload, group_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(mid, fromPeer, member, payloadStr, groupId, Date.now())
      stored++
    }
  }

  sendTo(fromPeer, { type: 'send_ok', messageId, status: delivered > 0 ? 'delivered' : 'stored', delivered, stored })
}

function handleReceipt(fromPeer, msg) {
  const { to, messageId, receiptType } = msg
  if (!to || !messageId) return
  pushToClient(to, { type: 'receipt', from: fromPeer, messageId, receiptType: receiptType || 'delivered' })
}

function handleFriendRequest(fromPeer, msg) {
  const { to, displayName } = msg
  if (!to) return
  pushToClient(to, { type: 'friend_request', from: fromPeer, displayName: displayName || fromPeer.slice(0, 12) })
  sendTo(fromPeer, { type: 'send_ok', status: 'sent' })
}

function handleAck(peerId, msg) {
  const { messageIds } = msg
  if (!Array.isArray(messageIds)) return
  const stmt = db.prepare(`UPDATE messages SET delivered = 1 WHERE message_id = ? AND to_peer = ?`)
  for (const id of messageIds) stmt.run(id, peerId)
}

// ── Push helpers ────────────────────────────────────────────────

function pushToClient(peerId, msg) {
  const client = clients.get(peerId)
  if (!client || client.ws.readyState !== 1) return false
  try { client.ws.send(JSON.stringify(msg)); return true } catch { return false }
}

function sendTo(peerId, msg) { pushToClient(peerId, msg) }

function pushPendingMessages(peerId) {
  const rows = db.prepare(`SELECT * FROM messages WHERE to_peer = ? AND delivered = 0 ORDER BY timestamp ASC LIMIT 100`).all(peerId)
  if (rows.length === 0) return
  console.log(`[relay] Pushing ${rows.length} pending message(s) to ${peerId.slice(0, 16)}...`)
  for (const row of rows) {
    const payload = row.group_id
      ? { type: 'group_message', from: row.from_peer, groupId: row.group_id, payload: row.payload, messageId: row.message_id, timestamp: row.timestamp }
      : { type: 'message', from: row.from_peer, payload: row.payload, messageId: row.message_id, timestamp: row.timestamp }
    if (pushToClient(peerId, payload)) {
      db.prepare(`UPDATE messages SET delivered = 1 WHERE message_id = ?`).run(row.message_id)
    } else break
  }
}

function getPeerId(ws) {
  for (const [peerId, client] of clients) {
    if (client.ws === ws) return peerId
  }
  return null
}

// ── Ping & Cleanup ──────────────────────────────────────────────

setInterval(() => {
  for (const [peerId, client] of clients) {
    if (client.ws.readyState !== 1) { clients.delete(peerId); continue }
    client.ws.ping()
  }
}, PING_INTERVAL_MS)

setInterval(() => {
  const cutoff = Math.floor((Date.now() - MESSAGE_TTL_MS) / 1000)
  const result = db.prepare(`DELETE FROM messages WHERE created_at < ?`).run(cutoff)
  if (result.changes > 0) console.log(`[relay] Cleaned ${result.changes} expired messages (72h TTL)`)
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
