/**
 * Cleanup service — periodic cleanup of old messages, files, and expired sessions.
 * Designed for low-resource servers (1 core, 1GB RAM).
 */
const fs = require('fs')
const path = require('path')
const config = require('./config')
const db = require('./db')

let _timer = null

function startCleanup(interval) {
  // Run once immediately
  runCleanup()
  // Then every interval
  _timer = setInterval(runCleanup, interval || config.CLEANUP_INTERVAL)
  console.log('[cleanup] Started, interval:', (interval || config.CLEANUP_INTERVAL) / 60000, 'min')
}

function stopCleanup() {
  if (_timer) { clearInterval(_timer); _timer = null }
}

function runCleanup() {
  try {
    const msgCount = cleanupMessages()
    const fileCount = cleanupFiles()
    const sessionCount = cleanupSessions()
    if (msgCount + fileCount + sessionCount > 0) {
      console.log(`[cleanup] Removed: ${msgCount} messages, ${fileCount} files, ${sessionCount} sessions`)
    }
  } catch (e) {
    console.error('[cleanup] Error:', e.message)
  }
}

/**
 * Delete messages older than MESSAGE_RETENTION_DAYS.
 */
function cleanupMessages() {
  const cutoff = Date.now() - config.MESSAGE_RETENTION_DAYS * 24 * 3600 * 1000
  const d = db.getDb()
  const result = d.prepare('DELETE FROM messages WHERE timestamp < ?').run(cutoff)
  // Also clean message_status for deleted messages
  d.prepare('DELETE FROM message_status WHERE message_id NOT IN (SELECT message_id FROM messages)').run()
  return result.changes
}

/**
 * Delete files older than FILE_RETENTION_DAYS or when total storage exceeds MAX_STORAGE.
 */
function cleanupFiles() {
  const d = db.getDb()
  let count = 0

  // 1. Delete files older than retention period
  const cutoff = Math.floor(Date.now() / 1000) - config.FILE_RETENTION_DAYS * 24 * 3600
  const old = d.prepare('SELECT file_id, path FROM files WHERE created_at < ?').all(cutoff)
  for (const f of old) {
    deleteFileFromDisk(f.path)
    d.prepare('DELETE FROM files WHERE file_id = ?').run(f.file_id)
    count++
  }

  // 2. If total storage still exceeds MAX_STORAGE, delete oldest files (FIFO)
  const totalSize = getDirSize(config.FILE_UPLOAD_DIR)
  if (totalSize > config.MAX_STORAGE) {
    const files = d.prepare('SELECT file_id, path, size FROM files ORDER BY created_at ASC').all()
    let freed = 0
    for (const f of files) {
      if (totalSize - freed <= config.MAX_STORAGE) break
      deleteFileFromDisk(f.path)
      d.prepare('DELETE FROM files WHERE file_id = ?').run(f.file_id)
      freed += f.size || 0
      count++
    }
  }

  return count
}

/**
 * Delete expired sessions (refresh token expired > 30 days ago).
 */
function cleanupSessions() {
  const d = db.getDb()
  const cutoff = Math.floor(Date.now() / 1000) - 30 * 24 * 3600
  const result = d.prepare('DELETE FROM sessions WHERE expires_at < ?').run(cutoff)
  return result.changes
}

function deleteFileFromDisk(filename) {
  try {
    const filePath = path.join(config.FILE_UPLOAD_DIR, filename)
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
  } catch {}
}

function getDirSize() {
  try {
    const d = db.getDb()
    const row = d.prepare('SELECT COALESCE(SUM(size), 0) as total FROM files').get()
    return row?.total || 0
  } catch {
    // Fallback to disk scan if DB query fails
    try {
      const dir = config.FILE_UPLOAD_DIR
      if (!fs.existsSync(dir)) return 0
      return fs.readdirSync(dir).reduce((total, f) => {
        try { return total + fs.statSync(path.join(dir, f)).size } catch { return total }
      }, 0)
    } catch { return 0 }
  }
}

module.exports = { startCleanup, stopCleanup, runCleanup, getDirSize }
