const http = require('http')
const path = require('path')
const zlib = require('zlib')
const Database = require('better-sqlite3')
const WebSocket = require('ws')
const fs = require('fs')

// ── Config ──────────────────────────────────────────────
const PORT = 3000
const STATS_KEY = process.env.STATS_KEY || 'zoyachat2026'
const DB_PATH = path.join(__dirname, 'heartbeat.db')
const PROBE_TIMEOUT_MS = 5000
const MAX_CONCURRENT_PROBES = 10
const RELAYS_PATH = path.join(__dirname, 'relays.json')

// ── Official Relay List (hot-reloaded from relays.json) ──
function loadRelays() {
  try {
    return JSON.parse(fs.readFileSync(RELAYS_PATH, 'utf-8'))
  } catch {
    return []
  }
}

// ── Database ────────────────────────────────────────────
const db = new Database(DB_PATH)
db.pragma('journal_mode = WAL')

db.exec(`
  CREATE TABLE IF NOT EXISTS heartbeats (
    id        TEXT NOT NULL,
    version   TEXT NOT NULL DEFAULT '',
    platform  TEXT NOT NULL DEFAULT '',
    event     TEXT NOT NULL DEFAULT '',
    date      TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    relay_mode     TEXT DEFAULT '',
    relay_public   INTEGER DEFAULT 0,
    relay_reachable INTEGER DEFAULT 0,
    PRIMARY KEY (id, date)
  )
`)
// For fast stats queries
db.exec(`CREATE INDEX IF NOT EXISTS idx_hb_date ON heartbeats(date)`)
db.exec(`CREATE INDEX IF NOT EXISTS idx_hb_id ON heartbeats(id)`)

// Probe stats table — persistent daily counters
db.exec(`
  CREATE TABLE IF NOT EXISTS probe_stats (
    date       TEXT NOT NULL,
    checks     INTEGER DEFAULT 0,
    reachable  INTEGER DEFAULT 0,
    unreachable INTEGER DEFAULT 0,
    PRIMARY KEY (date)
  )
`)

// Migrate: add relay columns if missing (safe for existing DBs)
try { db.exec(`ALTER TABLE heartbeats ADD COLUMN relay_mode TEXT DEFAULT ''`) } catch {}
try { db.exec(`ALTER TABLE heartbeats ADD COLUMN relay_public INTEGER DEFAULT 0`) } catch {}
try { db.exec(`ALTER TABLE heartbeats ADD COLUMN relay_reachable INTEGER DEFAULT 0`) } catch {}

const upsertStmt = db.prepare(`
  INSERT INTO heartbeats (id, version, platform, event, date, timestamp, relay_mode, relay_public, relay_reachable)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(id, date) DO UPDATE SET
    version   = excluded.version,
    platform  = excluded.platform,
    event     = excluded.event,
    timestamp = excluded.timestamp,
    relay_mode     = excluded.relay_mode,
    relay_public   = excluded.relay_public,
    relay_reachable = excluded.relay_reachable
`)

const probeStatsUpsert = db.prepare(`
  INSERT INTO probe_stats (date, checks, reachable, unreachable)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(date) DO UPDATE SET
    checks = probe_stats.checks + excluded.checks,
    reachable = probe_stats.reachable + excluded.reachable,
    unreachable = probe_stats.unreachable + excluded.unreachable
`)

// ── Stats queries ───────────────────────────────────────
const totalInstalls = db.prepare(`SELECT COUNT(DISTINCT id) AS cnt FROM heartbeats`)
const todayDAU = db.prepare(`SELECT COUNT(DISTINCT id) AS cnt FROM heartbeats WHERE date = ?`)
const weekDAU = db.prepare(`
  SELECT date, COUNT(DISTINCT id) AS cnt
  FROM heartbeats
  WHERE date >= ?
  GROUP BY date
  ORDER BY date
`)
const platformDist = db.prepare(`
  SELECT platform, COUNT(DISTINCT id) AS cnt
  FROM heartbeats
  GROUP BY platform
  ORDER BY cnt DESC
`)
const versionDist = db.prepare(`
  SELECT version, COUNT(DISTINCT id) AS cnt
  FROM heartbeats
  WHERE date >= ?
  GROUP BY version
  ORDER BY cnt DESC
`)
const probeStatsToday = db.prepare(`SELECT * FROM probe_stats WHERE date = ?`)
const relayStats = db.prepare(`
  SELECT
    COUNT(DISTINCT CASE WHEN relay_mode = 'host' THEN id END) AS hosts,
    COUNT(DISTINCT CASE WHEN relay_public = 1 THEN id END) AS with_public,
    COUNT(DISTINCT CASE WHEN relay_public = 1 AND relay_reachable = 0 THEN id END) AS public_unreachable
  FROM heartbeats WHERE date = ?
`)

function today() {
  return new Date().toISOString().slice(0, 10)
}

function daysAgo(n) {
  const d = new Date()
  d.setDate(d.getDate() - n)
  return d.toISOString().slice(0, 10)
}

// ── Probe logic ─────────────────────────────────────────

let activeProbes = 0

function isPrivateIp(ip) {
  return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.|::1|fc|fd|fe80)/.test(ip)
}

function parseTarget(target) {
  if (!target) return null

  // Remember original protocol
  const hadWss = target.startsWith('wss://')

  // Strip protocol prefix
  let stripped = target.replace(/^wss?:\/\//, '')
  // Remove path and trailing slash (e.g. host:port/path → host:port)
  stripped = stripped.replace(/\/.*$/, '')

  const match = stripped.match(/^([^:]+?)(?::(\d+))?$/)
  if (!match) return null
  const host = match[1]
  const port = match[2] ? parseInt(match[2]) : null

  // If port specified, must be in range
  if (port !== null && (port < 1 || port > 65535)) return null

  if (isPrivateIp(host)) return null

  // Determine protocol: use wss if original had wss:// or host is a domain without port (tunnels)
  const isDomain = /[a-zA-Z]/.test(host)
  const useWss = hadWss || (!port && isDomain)
  const finalPort = port || (useWss ? 443 : 80)

  return { host, port: finalPort, useWss }
}

function probeWebSocket(host, port, useWss) {
  return new Promise((resolve) => {
    const start = Date.now()
    const protocol = useWss ? 'wss' : 'ws'
    // Omit port for default ports to avoid SNI issues
    const portSuffix = (useWss && port === 443) || (!useWss && port === 80) ? '' : `:${port}`
    const url = `${protocol}://${host}${portSuffix}`
    let settled = false

    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      try { ws.close() } catch {}
      resolve({ reachable: false, error: 'ETIMEDOUT' })
    }, PROBE_TIMEOUT_MS)

    const ws = new WebSocket(url, { handshakeTimeout: PROBE_TIMEOUT_MS, rejectUnauthorized: false })

    ws.on('open', () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      const latency = Date.now() - start
      try { ws.close() } catch {}
      resolve({ reachable: true, latency_ms: latency })
    })

    ws.on('message', () => {
      // Relay sends a challenge on connect — 'open' already fired, ignore
    })

    ws.on('error', (err) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ reachable: false, error: err.code || err.message || 'UNKNOWN' })
    })
  })
}

// ── HTTP Server ─────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (req.method === 'OPTIONS') {
    res.writeHead(204)
    res.end()
    return
  }

  let url
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)
  } catch {
    res.writeHead(400)
    res.end('Bad Request')
    return
  }

  // POST /heartbeat
  if (req.method === 'POST' && url.pathname === '/heartbeat') {
    let body = ''
    req.on('data', c => { body += c; if (body.length > 4096) req.destroy() })
    req.on('end', () => {
      try {
        const { id, version, platform, event, relay_mode, relay_public, relay_reachable } = JSON.parse(body)
        if (!id || typeof id !== 'string' || id.length > 64) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end('{"error":"invalid id"}')
          return
        }
        upsertStmt.run(
          id,
          String(version || '').slice(0, 32),
          String(platform || '').slice(0, 32),
          String(event || '').slice(0, 32),
          today(),
          Math.floor(Date.now() / 1000),
          String(relay_mode || '').slice(0, 16),
          relay_public ? 1 : 0,
          relay_reachable ? 1 : 0
        )
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end('{"ok":true}')
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end('{"error":"bad request"}')
      }
    })
    return
  }

  // GET /probe?key=xxx[&target=HOST:PORT]
  // Unified probe: always returns { ok, network, relays, stats }
  // If target is provided, also returns { target: { reachable, latency_ms } }
  if (req.method === 'GET' && url.pathname === '/probe') {
    if (url.searchParams.get('key') !== STATS_KEY) {
      res.writeHead(403, { 'Content-Type': 'application/json' })
      res.end('{"error":"forbidden"}')
      return
    }

    const response = {
      ok: true,
      network: true,
      relays: loadRelays(),
      stats: { uptime: Math.floor(process.uptime()) },
    }

    const target = url.searchParams.get('target')
    if (target) {
      const parsed = parseTarget(target)
      if (!parsed) {
        response.target = { reachable: false, error: 'Invalid target', target }
      } else if (activeProbes >= MAX_CONCURRENT_PROBES) {
        response.target = { reachable: false, error: 'Too many concurrent probes', target }
      } else {
        activeProbes++
        try {
          const result = await probeWebSocket(parsed.host, parsed.port, parsed.useWss)
          const d = today()
          probeStatsUpsert.run(d, 1, result.reachable ? 1 : 0, result.reachable ? 0 : 1)
          response.target = { ...result, target }
        } catch (e) {
          response.target = { reachable: false, error: e.message, target }
        } finally {
          activeProbes--
        }
      }
    }

    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(response))
    return
  }

  // GET /stats?key=xxx
  if (req.method === 'GET' && url.pathname === '/stats') {
    if (url.searchParams.get('key') !== STATS_KEY) {
      res.writeHead(403, { 'Content-Type': 'application/json' })
      res.end('{"error":"forbidden"}')
      return
    }

    try {
      const format = url.searchParams.get('format')
      const t = today()
      const probe = probeStatsToday.get(t) || { checks: 0, reachable: 0, unreachable: 0 }
      const relay = relayStats.get(t) || { hosts: 0, with_public: 0, public_unreachable: 0 }
      const stats = {
        totalInstalls: totalInstalls.get()?.cnt || 0,
        todayDAU: todayDAU.get(t)?.cnt || 0,
        weekDAU: weekDAU.all(daysAgo(6)) || [],
        platforms: platformDist.all() || [],
        versions: versionDist.all(daysAgo(30)) || [],
        probe_checks_today: probe.checks || 0,
        probe_reachable: probe.reachable || 0,
        probe_unreachable: probe.unreachable || 0,
        relay_hosts_today: relay.hosts || 0,
        relay_with_public: relay.with_public || 0,
        relay_public_unreachable: relay.public_unreachable || 0,
        generatedAt: new Date().toISOString(),
      }

      if (format === 'json') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(stats, null, 2))
        return
      }

      // HTML dashboard — gzip to fit in fewer packets (MTU workaround)
      const html = renderHTML(stats)
      const acceptGzip = (req.headers['accept-encoding'] || '').includes('gzip')
      if (acceptGzip) {
        const compressed = zlib.gzipSync(html)
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'gzip',
          'Content-Length': String(compressed.length),
        })
        res.end(compressed)
      } else {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': String(Buffer.byteLength(html)),
        })
        res.end(html)
      }
    } catch (e) {
      console.error('[stats] Error:', e.message)
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Stats error: ' + e.message }))
    }
    return
  }

  // Health check
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end('{"status":"ok","service":"zoyachat-heartbeat"}')
    return
  }

  res.writeHead(404)
  res.end('Not Found')
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[heartbeat] Server running on http://0.0.0.0:${PORT}`)
  console.log(`[heartbeat] Stats dashboard: http://localhost:${PORT}/stats?key=${STATS_KEY}`)
  console.log(`[heartbeat] Probe endpoint: http://localhost:${PORT}/probe?target=HOST:PORT&key=${STATS_KEY}`)
})

// ── HTML Dashboard ──────────────────────────────────────
function renderHTML(stats) {
  const weekRows = stats.weekDAU.map(r =>
    `<tr><td>${r.date}</td><td>${r.cnt}</td><td><div class="bar" style="width:${Math.max(r.cnt * 3, 4)}px"></div></td></tr>`
  ).join('')

  const platformRows = stats.platforms.map(r =>
    `<tr><td>${esc(r.platform || 'unknown')}</td><td>${r.cnt}</td></tr>`
  ).join('')

  const versionRows = stats.versions.map(r =>
    `<tr><td>${esc(r.version || 'unknown')}</td><td>${r.cnt}</td></tr>`
  ).join('')

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>ZoyaChat Stats</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 32px; }
  h1 { color: #e8a000; margin-bottom: 8px; font-size: 24px; }
  .subtitle { color: #8b949e; margin-bottom: 32px; font-size: 13px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; }
  .card h2 { font-size: 14px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
  .big { font-size: 48px; font-weight: 700; color: #e8a000; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  td { padding: 6px 8px; border-bottom: 1px solid #21262d; font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  .bar { height: 16px; background: #e8a000; border-radius: 4px; min-width: 4px; }
</style>
</head>
<body>
  <h1>ZoyaChat Heartbeat</h1>
  <p class="subtitle">Generated: ${stats.generatedAt}</p>
  <div class="grid">
    <div class="card">
      <h2>Total Installs</h2>
      <div class="big">${stats.totalInstalls}</div>
    </div>
    <div class="card">
      <h2>Today DAU</h2>
      <div class="big">${stats.todayDAU}</div>
    </div>
    <div class="card" style="grid-column: span 2;">
      <h2>7-Day DAU Trend</h2>
      <table>${weekRows || '<tr><td colspan="3">No data yet</td></tr>'}</table>
    </div>
    <div class="card">
      <h2>Platform Distribution</h2>
      <table>${platformRows || '<tr><td colspan="2">No data yet</td></tr>'}</table>
    </div>
    <div class="card">
      <h2>Version Distribution (30d)</h2>
      <table>${versionRows || '<tr><td colspan="2">No data yet</td></tr>'}</table>
    </div>
    <div class="card">
      <h2>Probe Stats (Today)</h2>
      <table>
        <tr><td>Total Checks</td><td>${stats.probe_checks_today}</td></tr>
        <tr><td>Reachable</td><td style="color:#22c55e">${stats.probe_reachable}</td></tr>
        <tr><td>Unreachable</td><td style="color:#ef4444">${stats.probe_unreachable}</td></tr>
      </table>
    </div>
    <div class="card">
      <h2>Relay Stats (Today)</h2>
      <table>
        <tr><td>Hosts Online</td><td>${stats.relay_hosts_today}</td></tr>
        <tr><td>With Public IP</td><td>${stats.relay_with_public}</td></tr>
        <tr><td>Public Unreachable</td><td style="color:#ef4444">${stats.relay_public_unreachable}</td></tr>
      </table>
    </div>
  </div>
</body>
</html>`
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
