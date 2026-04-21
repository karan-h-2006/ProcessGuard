const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const JSON_FILE_PATH = path.join(__dirname, '../live_state.json');
const CONTROL_QUEUE_PATH = path.join(__dirname, '../control_actions.jsonl');
const WATCH_INTERVAL_MS = 1000;

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

let latestPayload = {
  generated_at: null,
  scan_number: 0,
  scan_interval_seconds: 0,
  thresholds: {
    max_memory_kb: 98304,
    max_fd_count: 36,
    max_socket_count: 32,
    max_threads: 18,
    max_cpu_percent: 45,
    max_children_per_ppid: 8,
    min_alert_score: 40,
  },
  summary: {
    process_count: 0,
    alert_count: 0,
    action_count: 0,
    fd_access_limited_count: 0,
  },
  processes: [],
};

function normalizePayload(payload) {
  if (Array.isArray(payload)) {
    return {
      ...latestPayload,
      processes: payload,
      summary: {
        ...latestPayload.summary,
        process_count: payload.length,
        alert_count: payload.filter((process) => process.alerted).length,
        action_count: payload.filter((process) => process.action_taken).length,
      },
    };
  }

  return {
    ...latestPayload,
    ...payload,
    thresholds: {
      ...latestPayload.thresholds,
      ...(payload.thresholds || {}),
    },
    summary: {
      ...latestPayload.summary,
      ...(payload.summary || {}),
    },
    processes: Array.isArray(payload.processes) ? payload.processes : [],
  };
}

function loadPayload() {
  if (!fs.existsSync(JSON_FILE_PATH)) {
    return latestPayload;
  }

  try {
    const rawData = fs.readFileSync(JSON_FILE_PATH, 'utf-8');
    return normalizePayload(JSON.parse(rawData));
  } catch (error) {
    console.error('Error reading JSON:', error.message);
    return latestPayload;
  }
}

function broadcastLatestPayload() {
  latestPayload = loadPayload();
  io.emit('processData', latestPayload);
}

io.on('connection', (socket) => {
  console.log('Frontend dashboard connected');
  socket.emit('processData', loadPayload());
});

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    generated_at: latestPayload.generated_at,
    process_count: latestPayload.summary.process_count,
    alert_count: latestPayload.summary.alert_count,
    action_count: latestPayload.summary.action_count,
  });
});

app.post('/api/actions', (req, res) => {
  const pid = Number(req.body?.pid);
  const action = String(req.body?.action || '').trim().toLowerCase();
  const allowedActions = new Set(['allow', 'continue', 'resume', 'pause', 'terminate', 'stop', 'kill']);

  if (!Number.isInteger(pid) || pid <= 0) {
    res.status(400).json({ ok: false, error: 'Invalid pid' });
    return;
  }

  if (!allowedActions.has(action)) {
    res.status(400).json({ ok: false, error: 'Invalid action' });
    return;
  }

  fs.appendFileSync(CONTROL_QUEUE_PATH, `${pid} ${action}\n`, 'utf8');
  io.emit('actionQueued', { pid, action });
  res.json({ ok: true, pid, action });
});

latestPayload = loadPayload();
fs.watchFile(JSON_FILE_PATH, { interval: WATCH_INTERVAL_MS }, broadcastLatestPayload);

server.on('close', () => {
  fs.unwatchFile(JSON_FILE_PATH, broadcastLatestPayload);
});

const PORT = 3001;
const ALT_PORT = 3002;

server
  .listen(PORT, () => {
    console.log('ProcessGuard Socket.IO server running on port', PORT);
  })
  .on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is already in use.`);
      console.error(`Try freeing it or use the fallback port ${ALT_PORT}.`);

      server.listen(ALT_PORT, () => {
        console.log('ProcessGuard Socket.IO server running on port', ALT_PORT);
      });
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });
