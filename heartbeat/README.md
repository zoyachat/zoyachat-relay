# ZoyaChat Heartbeat Server

Anonymous DAU tracking server. No user-identifiable data is collected.

## Setup

```bash
cd server/heartbeat
npm install
```

## Run

```bash
# Direct
node server.js

# With pm2 (recommended for production)
npm install -g pm2
pm2 start server.js --name zoyachat-heartbeat
pm2 save
pm2 startup
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STATS_KEY` | `zoyachat2026` | Password for /stats endpoint |

## API

### POST /heartbeat
```json
{ "id": "uuid", "version": "0.1.0", "platform": "win32", "event": "launch" }
```

### GET /stats?key=YOUR_KEY
HTML dashboard with DAU, installs, platform/version breakdown.

### GET /stats?key=YOUR_KEY&format=json
Same data as JSON.

## Deploy to Vultr (207.148.78.79)

```bash
scp -r server/heartbeat/ root@207.148.78.79:/opt/zoyachat-heartbeat/
ssh root@207.148.78.79
cd /opt/zoyachat-heartbeat
npm install --production
STATS_KEY=your_secret pm2 start server.js --name zoyachat-heartbeat
pm2 save
```

Data stored in `heartbeat.db` (SQLite, auto-created on first run).
