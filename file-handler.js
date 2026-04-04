/**
 * File handler — HTTP upload/download for images and files.
 */
const express = require('express')
const multer = require('multer')
const path = require('path')
const fs = require('fs')
const { v4: uuidv4 } = require('uuid')
const config = require('./config')
const db = require('./db')
const auth = require('./auth')

const router = express.Router()

// Ensure upload directory exists
fs.mkdirSync(config.FILE_UPLOAD_DIR, { recursive: true })

// Multer storage config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, config.FILE_UPLOAD_DIR),
  filename: (req, file, cb) => {
    const fileId = uuidv4()
    const ext = path.extname(file.originalname) || ''
    req._fileId = fileId
    cb(null, fileId + ext)
  },
})

const upload = multer({
  storage,
  limits: { fileSize: config.MAX_FILE_SIZE },
})

/**
 * POST /api/files/upload
 * Requires Authorization: Bearer <token>
 * Body: multipart/form-data with field "file"
 * Returns: { ok, fileId, fileName, fileSize, mimeType }
 */
let _uploadLock = false
router.post('/upload', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const user = auth.verifyToken(token)
  if (!user) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' })
  if (_uploadLock) return res.status(429).json({ ok: false, error: 'UPLOAD_BUSY' })
  _uploadLock = true

  // Check total storage before accepting upload
  const { getDirSize } = require('./cleanup')
  const currentSize = getDirSize(config.FILE_UPLOAD_DIR)
  if (currentSize >= config.MAX_STORAGE) {
    _uploadLock = false
    return res.status(413).json({ ok: false, error: 'STORAGE_FULL', reason: 'Server storage limit reached' })
  }

  upload.single('file')(req, res, (err) => {
    _uploadLock = false
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ ok: false, error: 'FILE_TOO_LARGE' })
      return res.status(400).json({ ok: false, error: err.message })
    }
    if (!req.file) return res.status(400).json({ ok: false, error: 'NO_FILE' })

    // Validate file type
    const ext = path.extname(req.file.originalname).toLowerCase().replace('.', '')
    if (ext && !config.ALLOWED_FILE_TYPES.includes(ext)) {
      try { fs.unlinkSync(path.join(config.FILE_UPLOAD_DIR, req.file.filename)) } catch {}
      return res.status(400).json({ ok: false, error: 'FILE_TYPE_NOT_ALLOWED', reason: `File type .${ext} is not allowed` })
    }

    const fileId = req._fileId
    const { originalname, size, mimetype, filename } = req.file
    db.insertFile(fileId, user.userId, originalname, size, mimetype, filename)

    try { db.insertAnalytics('file_upload', user.userId) } catch {}
    res.json({ ok: true, fileId, fileName: originalname, fileSize: size, mimeType: mimetype })
  })
})

/**
 * GET /api/files/:id
 * Requires Authorization: Bearer <token>
 * Supports Range requests for partial downloads.
 */
router.get('/:id', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const user = auth.verifyToken(token)
  if (!user) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' })

  const file = db.getFile(req.params.id)
  if (!file) return res.status(404).json({ ok: false, error: 'NOT_FOUND' })

  const filePath = path.join(config.FILE_UPLOAD_DIR, file.path)
  if (!fs.existsSync(filePath)) return res.status(404).json({ ok: false, error: 'FILE_MISSING' })

  res.setHeader('Content-Type', file.mime_type || 'application/octet-stream')
  res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(file.filename)}"`)
  res.sendFile(path.resolve(filePath))
})

module.exports = router
