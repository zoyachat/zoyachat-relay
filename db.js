/**
 * Server-side SQLite database — users, sessions, messages, groups, contacts, files, presence.
 */
const Database = require('better-sqlite3')
const fs = require('fs')
const path = require('path')
const config = require('./config')

let db

function init() {
  const dir = path.dirname(config.DB_PATH)
  fs.mkdirSync(dir, { recursive: true })
  db = new Database(config.DB_PATH)
  db.pragma('journal_mode = WAL')
  db.pragma('synchronous = NORMAL')
  db.pragma('foreign_keys = ON')

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      TEXT    NOT NULL UNIQUE,
      email        TEXT    NOT NULL DEFAULT '',
      username     TEXT    NOT NULL UNIQUE,
      password     TEXT    NOT NULL,
      display_name TEXT    NOT NULL DEFAULT '',
      avatar_color TEXT    NOT NULL DEFAULT '#8b5cf6',
      avatar_image TEXT    NOT NULL DEFAULT '',
      bio          TEXT    NOT NULL DEFAULT '',
      created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      is_deleted   INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       TEXT    NOT NULL,
      device_id     TEXT    NOT NULL,
      device_name   TEXT    NOT NULL DEFAULT '',
      access_token  TEXT    NOT NULL UNIQUE,
      refresh_token TEXT    NOT NULL UNIQUE,
      created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      expires_at    INTEGER NOT NULL,
      last_active   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_access ON sessions(access_token);

    CREATE TABLE IF NOT EXISTS messages (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      message_id TEXT    NOT NULL UNIQUE,
      from_user  TEXT    NOT NULL,
      to_user    TEXT,
      group_id   TEXT,
      content    TEXT    NOT NULL DEFAULT '',
      msg_type   TEXT    NOT NULL DEFAULT 'text',
      file_id    TEXT,
      file_name  TEXT,
      file_size  INTEGER,
      reply_to   TEXT,
      agent_id   TEXT,
      timestamp  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
    );
    CREATE INDEX IF NOT EXISTS idx_messages_to     ON messages(to_user, timestamp);
    CREATE INDEX IF NOT EXISTS idx_messages_group  ON messages(group_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_messages_from   ON messages(from_user, timestamp);

    CREATE TABLE IF NOT EXISTS message_status (
      message_id TEXT NOT NULL,
      user_id    TEXT NOT NULL,
      status     TEXT NOT NULL DEFAULT 'sent',
      updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      PRIMARY KEY (message_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS groups (
      group_id         TEXT PRIMARY KEY,
      name             TEXT NOT NULL DEFAULT '',
      description      TEXT NOT NULL DEFAULT '',
      avatar_color     TEXT NOT NULL DEFAULT '#8b5cf6',
      creator_id       TEXT NOT NULL,
      max_members      INTEGER NOT NULL DEFAULT 20,
      agent_id         TEXT    DEFAULT '',
      agent_reply_mode TEXT    DEFAULT 'mention',
      agent_gateway_url TEXT   DEFAULT '',
      context_messages INTEGER DEFAULT 20,
      announcement     TEXT    DEFAULT '',
      pinned_message   TEXT    DEFAULT '',
      created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      is_deleted       INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS group_members (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id     TEXT    NOT NULL,
      user_id      TEXT    NOT NULL,
      display_name TEXT    NOT NULL DEFAULT '',
      role         TEXT    NOT NULL DEFAULT 'member',
      is_muted     INTEGER NOT NULL DEFAULT 0,
      banned       INTEGER NOT NULL DEFAULT 0,
      joined_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      UNIQUE(group_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS contacts (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     TEXT NOT NULL,
      contact_id  TEXT NOT NULL,
      status      TEXT NOT NULL DEFAULT 'pending',
      remark_name TEXT NOT NULL DEFAULT '',
      created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      UNIQUE(user_id, contact_id)
    );

    CREATE TABLE IF NOT EXISTS friend_requests (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user    TEXT    NOT NULL,
      to_user      TEXT    NOT NULL,
      display_name TEXT    NOT NULL DEFAULT '',
      message      TEXT    NOT NULL DEFAULT '',
      status       TEXT    NOT NULL DEFAULT 'pending',
      created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_friend_req_to ON friend_requests(to_user, status);

    CREATE TABLE IF NOT EXISTS files (
      file_id    TEXT PRIMARY KEY,
      uploader   TEXT NOT NULL,
      filename   TEXT NOT NULL DEFAULT '',
      size       INTEGER NOT NULL DEFAULT 0,
      mime_type  TEXT NOT NULL DEFAULT '',
      path       TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS presence (
      user_id   TEXT PRIMARY KEY,
      is_online INTEGER NOT NULL DEFAULT 0,
      last_seen INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS analytics (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT    NOT NULL,
      user_id    TEXT,
      metadata   TEXT,
      ip_address TEXT,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_analytics_type_date ON analytics(event_type, created_at);
    CREATE INDEX IF NOT EXISTS idx_analytics_user ON analytics(user_id, created_at);
  `)

  // Migration: add email column to existing users tables
  try { db.prepare("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''").run() } catch {}

  console.log('[db] initialized at', config.DB_PATH)
  return db
}

function getDb() { return db }

// ── User queries ────────────────────────────────────────────────
function createUser(userId, username, passwordHash, displayName, email) {
  return db.prepare(
    'INSERT INTO users (user_id, email, username, password, display_name) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, email || '', username, passwordHash, displayName)
}

function getUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ? AND is_deleted = 0').get(username)
}

function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ? AND is_deleted = 0').get(email)
}

function getUserById(userId) {
  return db.prepare('SELECT * FROM users WHERE user_id = ? AND is_deleted = 0').get(userId)
}

function updateUsername(userId, newUsername) {
  db.prepare('UPDATE users SET username = ? WHERE user_id = ?').run(newUsername, userId)
}

function isUsernameAvailable(username, excludeUserId) {
  const row = db.prepare('SELECT COUNT(*) as count FROM users WHERE username = ? AND user_id != ? AND is_deleted = 0').get(username, excludeUserId || '')
  return (row?.count || 0) === 0
}

function searchUsers(query, limit = 20) {
  return db.prepare(
    'SELECT user_id, username, display_name, avatar_color, avatar_image, bio FROM users WHERE is_deleted = 0 AND (username LIKE ? OR display_name LIKE ?) LIMIT ?'
  ).all(`%${query}%`, `%${query}%`, limit)
}

function updateUserProfile(userId, fields) {
  const allowed = ['display_name', 'avatar_color', 'avatar_image', 'bio']
  const sets = []
  const vals = []
  for (const k of allowed) {
    if (fields[k] !== undefined) { sets.push(`${k} = ?`); vals.push(fields[k]) }
  }
  if (sets.length === 0) return
  vals.push(userId)
  db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE user_id = ?`).run(...vals)
}

// ── Session queries ──────────────────────────────────────────────
function createSession(userId, deviceId, deviceName, accessToken, refreshToken, expiresAt) {
  return db.prepare(
    'INSERT INTO sessions (user_id, device_id, device_name, access_token, refresh_token, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(userId, deviceId, deviceName, accessToken, refreshToken, expiresAt)
}

function getSessionByAccessToken(token) {
  return db.prepare('SELECT * FROM sessions WHERE access_token = ?').get(token)
}

function getSessionByRefreshToken(token) {
  return db.prepare('SELECT * FROM sessions WHERE refresh_token = ?').get(token)
}

function deleteSession(accessToken) {
  db.prepare('DELETE FROM sessions WHERE access_token = ?').run(accessToken)
}

function deleteSessionsByUser(userId) {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId)
}

function getUserDevices(userId) {
  return db.prepare('SELECT device_id, device_name, last_active FROM sessions WHERE user_id = ? ORDER BY last_active DESC').all(userId)
}

function touchSession(accessToken) {
  db.prepare('UPDATE sessions SET last_active = strftime(\'%s\',\'now\') WHERE access_token = ?').run(accessToken)
}

// ── Message queries ──────────────────────────────────────────────
function insertMessage(messageId, fromUser, toUser, groupId, content, msgType, fileId, fileName, fileSize, replyTo, agentId) {
  return db.prepare(
    'INSERT OR IGNORE INTO messages (message_id, from_user, to_user, group_id, content, msg_type, file_id, file_name, file_size, reply_to, agent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(messageId, fromUser, toUser, groupId, content, msgType, fileId || null, fileName || null, fileSize || null, replyTo || null, agentId || null)
}

function getMessagesForUser(userId, sinceTimestamp, limit) {
  return db.prepare(
    'SELECT * FROM messages WHERE (to_user = ? OR from_user = ?) AND timestamp > ? ORDER BY timestamp ASC LIMIT ?'
  ).all(userId, userId, sinceTimestamp, limit || config.MESSAGE_SYNC_LIMIT)
}

function getGroupMessages(groupId, sinceTimestamp, limit) {
  return db.prepare(
    'SELECT * FROM messages WHERE group_id = ? AND timestamp > ? ORDER BY timestamp ASC LIMIT ?'
  ).all(groupId, sinceTimestamp, limit || config.MESSAGE_SYNC_LIMIT)
}

function getRecentGroupMessages(groupId, limit) {
  return db.prepare(
    'SELECT * FROM messages WHERE group_id = ? ORDER BY timestamp DESC LIMIT ?'
  ).all(groupId, limit)
}

function setMessageStatus(messageId, userId, status) {
  db.prepare(
    'INSERT OR REPLACE INTO message_status (message_id, user_id, status, updated_at) VALUES (?, ?, ?, strftime(\'%s\',\'now\'))'
  ).run(messageId, userId, status)
}

// ── Group queries ────────────────────────────────────────────────
function createGroup(groupId, name, description, avatarColor, creatorId, maxMembers) {
  db.prepare(
    'INSERT INTO groups (group_id, name, description, avatar_color, creator_id, max_members) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(groupId, name, description, avatarColor, creatorId, maxMembers)
}

function getGroup(groupId) {
  return db.prepare('SELECT * FROM groups WHERE group_id = ? AND is_deleted = 0').get(groupId)
}

function updateGroup(groupId, fields) {
  const allowed = ['name', 'description', 'avatar_color', 'max_members', 'agent_id', 'agent_reply_mode', 'agent_gateway_url', 'context_messages', 'announcement', 'pinned_message']
  const sets = []
  const vals = []
  for (const k of allowed) {
    if (fields[k] !== undefined) { sets.push(`${k} = ?`); vals.push(fields[k]) }
  }
  if (sets.length === 0) return
  vals.push(groupId)
  db.prepare(`UPDATE groups SET ${sets.join(', ')} WHERE group_id = ?`).run(...vals)
}

function deleteGroup(groupId) {
  db.prepare('UPDATE groups SET is_deleted = 1 WHERE group_id = ?').run(groupId)
}

function addGroupMember(groupId, userId, displayName, role) {
  db.prepare(
    'INSERT OR IGNORE INTO group_members (group_id, user_id, display_name, role) VALUES (?, ?, ?, ?)'
  ).run(groupId, userId, displayName || '', role || 'member')
}

function removeGroupMember(groupId, userId) {
  db.prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?').run(groupId, userId)
}

function getGroupMembers(groupId) {
  return db.prepare('SELECT * FROM group_members WHERE group_id = ? AND banned = 0').all(groupId)
}

function getGroupMember(groupId, userId) {
  return db.prepare('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?').get(groupId, userId)
}

function getUserGroups(userId) {
  return db.prepare(
    `SELECT g.* FROM groups g
     JOIN group_members gm ON g.group_id = gm.group_id
     WHERE gm.user_id = ? AND g.is_deleted = 0 AND gm.banned = 0`
  ).all(userId)
}

function updateGroupMember(groupId, userId, fields) {
  const allowed = ['role', 'is_muted', 'banned', 'display_name']
  const sets = []
  const vals = []
  for (const k of allowed) {
    if (fields[k] !== undefined) { sets.push(`${k} = ?`); vals.push(fields[k]) }
  }
  if (sets.length === 0) return
  vals.push(groupId, userId)
  db.prepare(`UPDATE group_members SET ${sets.join(', ')} WHERE group_id = ? AND user_id = ?`).run(...vals)
}

// ── Contact / Friend queries ─────────────────────────────────────
function addContact(userId, contactId, status) {
  db.prepare(
    'INSERT OR REPLACE INTO contacts (user_id, contact_id, status) VALUES (?, ?, ?)'
  ).run(userId, contactId, status || 'accepted')
}

function getContacts(userId) {
  return db.prepare(
    `SELECT c.*, u.username, u.display_name, u.avatar_color, u.avatar_image, u.bio
     FROM contacts c JOIN users u ON c.contact_id = u.user_id
     WHERE c.user_id = ? AND c.status = 'accepted' AND u.is_deleted = 0`
  ).all(userId)
}

function getContact(userId, contactId) {
  return db.prepare('SELECT * FROM contacts WHERE user_id = ? AND contact_id = ?').get(userId, contactId)
}

function updateContact(userId, contactId, fields) {
  const allowed = ['status', 'remark_name']
  const sets = []
  const vals = []
  for (const k of allowed) {
    if (fields[k] !== undefined) { sets.push(`${k} = ?`); vals.push(fields[k]) }
  }
  if (sets.length === 0) return
  vals.push(userId, contactId)
  db.prepare(`UPDATE contacts SET ${sets.join(', ')} WHERE user_id = ? AND contact_id = ?`).run(...vals)
}

function deleteContact(userId, contactId) {
  db.prepare('DELETE FROM contacts WHERE user_id = ? AND contact_id = ?').run(userId, contactId)
}

function createFriendRequest(fromUser, toUser, displayName, message) {
  return db.prepare(
    'INSERT INTO friend_requests (from_user, to_user, display_name, message) VALUES (?, ?, ?, ?)'
  ).run(fromUser, toUser, displayName || '', message || '')
}

function getFriendRequests(userId, status) {
  return db.prepare(
    `SELECT fr.*, u.username, u.avatar_color, u.avatar_image
     FROM friend_requests fr JOIN users u ON fr.from_user = u.user_id
     WHERE fr.to_user = ? AND fr.status = ? ORDER BY fr.created_at DESC`
  ).all(userId, status || 'pending')
}

function getFriendRequest(id) {
  return db.prepare('SELECT * FROM friend_requests WHERE id = ?').get(id)
}

function updateFriendRequest(id, status) {
  db.prepare('UPDATE friend_requests SET status = ? WHERE id = ?').run(status, id)
}

function getPendingFriendRequestCount(userId) {
  const row = db.prepare("SELECT COUNT(*) as count FROM friend_requests WHERE to_user = ? AND status = 'pending'").get(userId)
  return row?.count || 0
}

// ── File queries ─────────────────────────────────────────────────
function insertFile(fileId, uploader, filename, size, mimeType, filePath) {
  db.prepare(
    'INSERT INTO files (file_id, uploader, filename, size, mime_type, path) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(fileId, uploader, filename, size, mimeType, filePath)
}

function getFile(fileId) {
  return db.prepare('SELECT * FROM files WHERE file_id = ?').get(fileId)
}

// ── Presence queries ─────────────────────────────────────────────
function setPresence(userId, isOnline) {
  db.prepare(
    'INSERT OR REPLACE INTO presence (user_id, is_online, last_seen) VALUES (?, ?, strftime(\'%s\',\'now\'))'
  ).run(userId, isOnline ? 1 : 0)
}

function getPresence(userIds) {
  if (!userIds.length) return []
  const placeholders = userIds.map(() => '?').join(',')
  return db.prepare(`SELECT * FROM presence WHERE user_id IN (${placeholders})`).all(...userIds)
}

// ── Analytics ────────────────────────────────────────────────
function insertAnalytics(eventType, userId, metadata, ip) {
  db.prepare('INSERT INTO analytics (event_type, user_id, metadata, ip_address) VALUES (?, ?, ?, ?)').run(eventType, userId || null, metadata || null, ip || null)
}

function getAnalyticsCount(eventType, sinceSec) {
  return db.prepare('SELECT COUNT(*) as count FROM analytics WHERE event_type = ? AND created_at >= ?').get(eventType, sinceSec)?.count || 0
}

function getDAU(sinceSec) {
  return db.prepare("SELECT COUNT(DISTINCT user_id) as count FROM analytics WHERE event_type IN ('login','ws_connect','message_send') AND created_at >= ?").get(sinceSec)?.count || 0
}

function getAllUsers() {
  return db.prepare('SELECT user_id, email, username, display_name, created_at FROM users WHERE is_deleted = 0 ORDER BY created_at DESC').all()
}

function getDailyActiveUsers(days) {
  return db.prepare(`SELECT date(created_at, 'unixepoch') as day, COUNT(DISTINCT user_id) as dau FROM analytics WHERE event_type IN ('login','ws_connect','message_send') AND created_at >= ? GROUP BY day ORDER BY day`).all(Math.floor(Date.now() / 1000) - days * 86400)
}

module.exports = {
  init, getDb,
  // Users
  createUser, getUserByUsername, getUserByEmail, getUserById, searchUsers, updateUserProfile,
  updateUsername, isUsernameAvailable,
  // Sessions
  createSession, getSessionByAccessToken, getSessionByRefreshToken,
  deleteSession, deleteSessionsByUser, getUserDevices, touchSession,
  // Messages
  insertMessage, getMessagesForUser, getGroupMessages, getRecentGroupMessages, setMessageStatus,
  // Groups
  createGroup, getGroup, updateGroup, deleteGroup,
  addGroupMember, removeGroupMember, getGroupMembers, getGroupMember,
  getUserGroups, updateGroupMember,
  // Contacts / Friends
  addContact, getContacts, getContact, updateContact, deleteContact,
  createFriendRequest, getFriendRequests, getFriendRequest, updateFriendRequest,
  getPendingFriendRequestCount,
  // Files
  insertFile, getFile,
  // Presence
  setPresence, getPresence,
  // Analytics
  insertAnalytics, getAnalyticsCount, getDAU, getAllUsers, getDailyActiveUsers,
}
