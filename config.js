/**
 * Server configuration — all tunables in one place.
 * Override via environment variables.
 */
const config = {
  PORT:           parseInt(process.env.PORT           || '3000'),
  DB_PATH:        process.env.DB_PATH                 || './data/server.db',
  JWT_SECRET:     process.env.JWT_SECRET              || 'zoyachat-dev-secret-change-in-production',
  ACCESS_TOKEN_EXPIRES:  process.env.ACCESS_TOKEN_EXPIRES  || '7d',
  REFRESH_TOKEN_EXPIRES: process.env.REFRESH_TOKEN_EXPIRES || '30d',
  BCRYPT_ROUNDS:  parseInt(process.env.BCRYPT_ROUNDS  || '12'),
  PING_INTERVAL:  30000,
  PING_TIMEOUT:   60000,
  MAX_CONNECTIONS: parseInt(process.env.MAX_CONNECTIONS || '100'),
  MAX_CONNECTIONS_PER_USER: parseInt(process.env.MAX_CONNECTIONS_PER_USER || '5'),
  FILE_UPLOAD_DIR: process.env.FILE_UPLOAD_DIR         || './data/files',
  MAX_FILE_SIZE:   parseInt(process.env.MAX_FILE_SIZE  || String(20 * 1024 * 1024)),
  MAX_STORAGE:     parseInt(process.env.MAX_STORAGE    || String(100 * 1024 * 1024)),
  MESSAGE_RETENTION_DAYS: parseInt(process.env.MESSAGE_RETENTION_DAYS || '7'),
  FILE_RETENTION_DAYS:    parseInt(process.env.FILE_RETENTION_DAYS    || '7'),
  ALLOWED_FILE_TYPES: (process.env.ALLOWED_FILE_TYPES || 'jpg,jpeg,png,gif,webp,pdf,doc,docx,xls,xlsx,ppt,pptx,txt,zip,rar,7z').split(','),
  CLEANUP_INTERVAL: 60 * 60 * 1000,
  MESSAGE_SYNC_LIMIT: 500,
  STATS_KEY: process.env.STATS_KEY || 'zoyachat2026',
}

// Production safety check
if (process.env.NODE_ENV === 'production' && config.JWT_SECRET === 'zoyachat-dev-secret-change-in-production') {
  console.error('[FATAL] JWT_SECRET must be set in production! Set JWT_SECRET env var.')
  process.exit(1)
}

module.exports = config
