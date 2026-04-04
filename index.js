/**
 * ZoyaChat Server — Entry point.
 * Starts HTTP (Express) + WebSocket (ws) servers.
 */
const http = require('http')
const express = require('express')
const { WebSocketServer } = require('ws')
const config = require('./config')
const db = require('./db')
const authModule = require('./auth')
const wsHandler = require('./ws-handler')
const fileHandler = require('./file-handler')
const cleanup = require('./cleanup')

// ── Security check ──
if (config.JWT_SECRET === 'zoyachat-dev-secret-change-in-production') {
  console.warn('[server] WARNING: Using default JWT_SECRET. Set JWT_SECRET env var for production!')
}

// ── Init DB ──
db.init()

// ── Express app (HTTP API) ──
const app = express()
app.use(express.json())

// CORS — allow all origins in dev
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})

// ── Rate limiting (in-memory, per-IP) ──
const rateLimitMap = new Map()
function rateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress
    const now = Date.now()
    let entry = rateLimitMap.get(ip)
    if (!entry || now - entry.start > windowMs) {
      entry = { start: now, count: 0 }
      rateLimitMap.set(ip, entry)
    }
    entry.count++
    if (entry.count > maxRequests) {
      return res.status(429).json({ ok: false, error: 'RATE_LIMITED', reason: 'Too many requests' })
    }
    next()
  }
}
// Clean up rate limit map periodically
setInterval(() => {
  const now = Date.now()
  for (const [ip, entry] of rateLimitMap) {
    if (now - entry.start > 60000) rateLimitMap.delete(ip)
  }
}, 60000)

// ── Auth routes ──
app.post('/api/auth/register', rateLimit(5, 3600000), async (req, res) => {
  const { email, username, password, displayName, deviceId, deviceName } = req.body
  const result = await authModule.register(email, username, password, displayName, deviceId, deviceName)
  if (result.ok) db.insertAnalytics('register', result.userId, null, req.ip)
  res.json(result)
})

app.post('/api/auth/login', rateLimit(10, 60000), async (req, res) => {
  const { email, password, deviceId, deviceName } = req.body
  const result = await authModule.login(email, password, deviceId, deviceName)
  if (result.ok) db.insertAnalytics('login', result.userId, null, req.ip)
  res.json(result)
})

app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body
  const result = authModule.refresh(refreshToken)
  res.json(result)
})

app.post('/api/auth/logout', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const result = authModule.logout(token)
  res.json(result)
})

// ── User search ──
app.get('/api/users/search', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const user = authModule.verifyToken(token)
  if (!user) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' })
  const results = db.searchUsers(req.query.q || '', 20)
  res.json({ ok: true, users: results })
})

// ── File routes ──
app.use('/api/files', fileHandler)

// ── Username change ──
app.put('/api/users/username', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const user = authModule.verifyToken(token)
  if (!user) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' })
  const { newUsername } = req.body
  if (!newUsername || newUsername.length < 3 || newUsername.length > 32) return res.json({ ok: false, error: 'INVALID_USERNAME' })
  if (!/^[a-zA-Z0-9_.-]+$/.test(newUsername)) return res.json({ ok: false, error: 'INVALID_USERNAME' })
  if (!db.isUsernameAvailable(newUsername, user.userId)) return res.json({ ok: false, error: 'USERNAME_TAKEN' })
  db.updateUsername(user.userId, newUsername)
  res.json({ ok: true, username: newUsername })
})

// ── Health check ──
app.get('/api/health', (req, res) => {
  res.json({ ok: true, online: wsHandler.getOnlineUserCount(), uptime: process.uptime() })
})

// ── Stats dashboard ──
app.get('/stats', (req, res) => {
  if (req.query.key !== config.STATS_KEY) return res.status(403).send('Forbidden')
  const statsHandler = require('./stats-handler')
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.send(statsHandler.renderDashboard(wsHandler.getOnlineUserCount()))
})

// ── Start servers ──
const httpServer = http.createServer(app)
const wss = new WebSocketServer({ server: httpServer })

wsHandler.init(wss)

httpServer.listen(config.PORT, () => {
  console.log(`[server] ZoyaChat server running on port ${config.PORT}`)
  console.log(`[server] HTTP API: http://localhost:${config.PORT}/api`)
  console.log(`[server] WebSocket: ws://localhost:${config.PORT}`)
  cleanup.startCleanup(config.CLEANUP_INTERVAL)
})
