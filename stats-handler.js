/**
 * Stats dashboard — renders HTML page with analytics data.
 * Access via GET /stats?key=<STATS_KEY>
 */
const db = require('./db')
const { getDirSize } = require('./cleanup')

function renderDashboard(onlineCount) {
  const now = Math.floor(Date.now() / 1000)
  const todayStart = now - (now % 86400)
  const weekAgo = now - 7 * 86400
  const monthAgo = now - 30 * 86400

  const dau = db.getDAU(todayStart)
  const wau = db.getDAU(weekAgo)
  const mau = db.getDAU(monthAgo)

  const allUsers = db.getAllUsers()
  const totalUsers = allUsers.length
  const todayRegistered = allUsers.filter(u => u.created_at >= todayStart).length

  const todayMessages = db.getAnalyticsCount('message_send', todayStart)
  const todayUploads = db.getAnalyticsCount('file_upload', todayStart)
  const todayGroups = db.getAnalyticsCount('group_create', todayStart)

  const trend = db.getDailyActiveUsers(30)
  const maxDAU = Math.max(1, ...trend.map(d => d.dau))

  const mem = process.memoryUsage()
  const uptime = process.uptime()
  const uptimeStr = `${Math.floor(uptime / 86400)}d ${Math.floor((uptime % 86400) / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`
  const memMB = (mem.rss / 1048576).toFixed(1)
  const storageMB = (getDirSize() / 1048576).toFixed(1)

  let dbSizeMB = '?'
  try { const fs = require('fs'); dbSizeMB = (fs.statSync(require('./config').DB_PATH).size / 1048576).toFixed(1) } catch {}

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="refresh" content="60">
<title>ZoyaChat Stats</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,system-ui,sans-serif;background:#0d0d1a;color:#e0e0e0;padding:20px;max-width:900px;margin:auto}
  h1{color:#d4a017;margin-bottom:16px;font-size:20px}h2{font-size:14px;color:#888;margin:16px 0 8px;text-transform:uppercase;letter-spacing:1px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:16px}
  .card{background:#1a1a2e;border:1px solid #333;border-radius:8px;padding:12px;text-align:center}
  .card .num{font-size:24px;font-weight:700;color:#d4a017}.card .lbl{font-size:10px;color:#888;margin-top:4px}
  table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:6px 8px;border-bottom:1px solid #222;text-align:left}
  th{color:#888;font-weight:600}tr:hover{background:#1a1a2e}.bar{display:inline-block;background:#d4a017;height:14px;border-radius:2px;min-width:2px}
  .sys{display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px}.sys div{background:#1a1a2e;border:1px solid #333;border-radius:6px;padding:8px}
  .sys .k{color:#888}.sys .v{color:#e0e0e0;font-weight:600}
</style></head><body>
<h1>ZoyaChat Stats Dashboard</h1>

<div class="cards">
  <div class="card"><div class="num">${dau}</div><div class="lbl">DAU (Today)</div></div>
  <div class="card"><div class="num">${wau}</div><div class="lbl">WAU (7 days)</div></div>
  <div class="card"><div class="num">${mau}</div><div class="lbl">MAU (30 days)</div></div>
  <div class="card"><div class="num">${totalUsers}</div><div class="lbl">Total Users</div></div>
  <div class="card"><div class="num">${todayRegistered}</div><div class="lbl">New Today</div></div>
  <div class="card"><div class="num">${onlineCount}</div><div class="lbl">Online Now</div></div>
</div>

<div class="cards">
  <div class="card"><div class="num">${todayMessages}</div><div class="lbl">Messages Today</div></div>
  <div class="card"><div class="num">${todayUploads}</div><div class="lbl">Uploads Today</div></div>
  <div class="card"><div class="num">${todayGroups}</div><div class="lbl">Groups Today</div></div>
</div>

<h2>DAU Trend (30 days)</h2>
<table>${trend.map(d => `<tr><td style="width:90px;color:#888">${d.day}</td><td><span class="bar" style="width:${Math.round(d.dau / maxDAU * 200)}px"></span> ${d.dau}</td></tr>`).join('')}</table>

<h2>Registered Users</h2>
<table><tr><th>#</th><th>Username</th><th>Email</th><th>Display Name</th><th>Registered</th></tr>
${allUsers.slice(0, 100).map((u, i) => `<tr><td>${i + 1}</td><td>${esc(u.username)}</td><td>${esc(u.email || '—')}</td><td>${esc(u.display_name || '—')}</td><td>${new Date(u.created_at * 1000).toISOString().slice(0, 16).replace('T', ' ')}</td></tr>`).join('')}
</table>

<h2>System</h2>
<div class="sys">
  <div><span class="k">Uptime:</span> <span class="v">${uptimeStr}</span></div>
  <div><span class="k">Memory:</span> <span class="v">${memMB} MB</span></div>
  <div><span class="k">Database:</span> <span class="v">${dbSizeMB} MB</span></div>
  <div><span class="k">File Storage:</span> <span class="v">${storageMB} / 100 MB</span></div>
</div>

<p style="text-align:center;color:#444;font-size:10px;margin-top:20px">Auto-refresh every 60s</p>
</body></html>`
}

function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;') }

module.exports = { renderDashboard }
