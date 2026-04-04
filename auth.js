/**
 * Authentication — register, login, JWT token management.
 */
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { v4: uuidv4 } = require('uuid')
const config = require('./config')
const db = require('./db')

/**
 * Register a new user.
 * @returns {{ ok, userId, accessToken, refreshToken } | { ok: false, error }}
 */
async function register(email, username, password, displayName, deviceId, deviceName) {
  if (!email || !username || !password) return { ok: false, error: 'MISSING_FIELDS' }
  email = email.trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { ok: false, error: 'INVALID_EMAIL', reason: 'Invalid email format' }
  if (username.length < 3 || username.length > 32) return { ok: false, error: 'INVALID_USERNAME', reason: 'Username must be 3-32 characters' }
  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) return { ok: false, error: 'INVALID_USERNAME', reason: 'Username can only contain letters, numbers, dots, hyphens, underscores' }
  if (password.length < 8) return { ok: false, error: 'WEAK_PASSWORD', reason: 'Password must be at least 8 characters' }
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) return { ok: false, error: 'WEAK_PASSWORD', reason: 'Password must contain at least one letter and one number' }

  if (db.getUserByEmail(email)) return { ok: false, error: 'EMAIL_TAKEN' }
  if (db.getUserByUsername(username)) return { ok: false, error: 'USERNAME_TAKEN' }

  const userId = uuidv4()
  const passwordHash = await bcrypt.hash(password, config.BCRYPT_ROUNDS)
  db.createUser(userId, username, passwordHash, displayName || username, email)
  db.setPresence(userId, false)

  const tokens = issueTokens(userId, deviceId || uuidv4(), deviceName || '')
  return { ok: true, userId, username, ...tokens }
}

/**
 * Login with email + password.
 */
async function login(email, password, deviceId, deviceName) {
  if (!email || !password) return { ok: false, error: 'MISSING_FIELDS' }
  email = email.trim().toLowerCase()

  const user = db.getUserByEmail(email)
  if (!user) return { ok: false, error: 'INVALID_CREDENTIALS' }

  if (!await bcrypt.compare(password, user.password)) return { ok: false, error: 'INVALID_CREDENTIALS' }

  const tokens = issueTokens(user.user_id, deviceId || uuidv4(), deviceName || '')
  return { ok: true, userId: user.user_id, username: user.username, displayName: user.display_name, ...tokens }
}

/**
 * Issue access + refresh tokens and create a session.
 */
function issueTokens(userId, deviceId, deviceName) {
  const accessToken = jwt.sign({ userId, deviceId, type: 'access' }, config.JWT_SECRET, { expiresIn: config.ACCESS_TOKEN_EXPIRES })
  const refreshToken = jwt.sign({ userId, deviceId, type: 'refresh' }, config.JWT_SECRET, { expiresIn: config.REFRESH_TOKEN_EXPIRES })
  const decoded = jwt.decode(accessToken)
  const expiresAt = decoded.exp

  db.createSession(userId, deviceId, deviceName, accessToken, refreshToken, expiresAt)
  return { accessToken, refreshToken }
}

/**
 * Verify an access token. Returns { userId, deviceId } or null.
 */
function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET)
    if (decoded.type !== 'access') return null
    // Check session exists in DB (allows logout/revocation)
    const session = db.getSessionByAccessToken(token)
    if (!session) return null
    db.touchSession(token)
    return { userId: decoded.userId, deviceId: decoded.deviceId }
  } catch {
    return null
  }
}

/**
 * Refresh an access token using a refresh token.
 * @returns {{ ok, accessToken, refreshToken } | { ok: false, error }}
 */
function refresh(refreshTokenStr) {
  try {
    const decoded = jwt.verify(refreshTokenStr, config.JWT_SECRET)
    if (decoded.type !== 'refresh') return { ok: false, error: 'INVALID_TOKEN' }

    const session = db.getSessionByRefreshToken(refreshTokenStr)
    if (!session) return { ok: false, error: 'SESSION_NOT_FOUND' }

    // Delete old session and issue new tokens
    db.deleteSession(session.access_token)
    const tokens = issueTokens(decoded.userId, decoded.deviceId, session.device_name)
    return { ok: true, ...tokens }
  } catch {
    return { ok: false, error: 'INVALID_TOKEN' }
  }
}

/**
 * Logout — delete session by access token.
 */
function logout(accessToken) {
  db.deleteSession(accessToken)
  return { ok: true }
}

module.exports = { register, login, verifyToken, refresh, logout }
