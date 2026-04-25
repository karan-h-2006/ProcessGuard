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
const SANDBOX_EVENTS_PATH = path.join(__dirname, '../sandbox_events.jsonl');
const SANDBOX_ARTIFACTS_PATH = path.join(__dirname, '../sandbox_artifacts.jsonl');
const SANDBOX_ARTIFACT_DIR = path.join(__dirname, '../sandbox_workspace/artifacts');
const PROCESS_LOG_PATH = path.join(__dirname, '../processguard.log');
const WATCH_INTERVAL_MS = 1000;
const STATIC_DIR = path.join(__dirname, 'public');

app.use(express.json());
app.use(express.static(STATIC_DIR));
app.use('/sandbox-artifacts', express.static(SANDBOX_ARTIFACT_DIR));
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
    filtered_dead_count: 0,
    stale_process_count: 0,
  },
  processes: [],
  snapshot_age_seconds: null,
  snapshot_status: 'waiting',
};
let latestSandboxEvents = [];
let latestSandboxArtifacts = [];

function canInspectLinuxProc() {
  return process.platform === 'linux' && fs.existsSync('/proc');
}

function readLinuxProcessState(pid) {
  const statusPath = `/proc/${pid}/status`;

  if (!canInspectLinuxProc() || !fs.existsSync(statusPath)) {
    return null;
  }

  try {
    const lines = fs.readFileSync(statusPath, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      if (line.startsWith('State:')) {
        const match = line.match(/^State:\s+([A-Z])/);
        return match ? match[1] : null;
      }
    }
  } catch (_error) {
    return null;
  }

  return null;
}

function pidIsLive(pid) {
  if (!Number.isInteger(pid) || pid <= 0 || !canInspectLinuxProc()) {
    return true;
  }

  const procDir = `/proc/${pid}`;
  if (!fs.existsSync(procDir)) {
    return false;
  }

  const stateCode = readLinuxProcessState(pid);
  return stateCode !== 'Z' && stateCode !== 'X';
}

function computeSnapshotAgeSeconds(generatedAt) {
  if (!generatedAt) {
    return null;
  }

  const generatedTime = new Date(generatedAt).getTime();
  if (!Number.isFinite(generatedTime)) {
    return null;
  }

  return Math.max(0, Math.round((Date.now() - generatedTime) / 1000));
}

function deriveSnapshotStatus(generatedAt, intervalSeconds) {
  const ageSeconds = computeSnapshotAgeSeconds(generatedAt);

  if (ageSeconds == null) {
    return { ageSeconds: null, status: 'waiting' };
  }

  if (ageSeconds > Math.max((Number(intervalSeconds) || 0) * 3, 8)) {
    return { ageSeconds, status: 'stale' };
  }

  return { ageSeconds, status: 'live' };
}

function readJsonLines(filePath, limit = 20) {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  try {
    return fs.readFileSync(filePath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-limit)
      .map((line) => JSON.parse(line));
  } catch (error) {
    console.error(`Error reading ${path.basename(filePath)}:`, error.message);
    return [];
  }
}

function loadRecentSandboxEvents() {
  return readJsonLines(SANDBOX_EVENTS_PATH, 20).reverse();
}

function loadRecentSandboxArtifacts() {
  return readJsonLines(SANDBOX_ARTIFACTS_PATH, 20).reverse();
}

function loadTimelineForPid(pid) {
  if (!fs.existsSync(PROCESS_LOG_PATH)) {
    return [];
  }

  const lines = fs.readFileSync(PROCESS_LOG_PATH, 'utf8').split(/\r?\n/).filter(Boolean).slice(-500);
  const events = [];

  for (const line of lines) {
    if (!line.includes(`pid=${pid}`)) {
      continue;
    }

    const timestampMatch = line.match(/^\[(.+?)\]\s+/);
    const message = line.replace(/^\[.+?\]\s+/, '');
    let type = 'log';

    if (message.startsWith('THREAT ')) type = 'alert';
    else if (message.startsWith('ACTION SKIPPED ')) type = 'protected';
    else if (message.startsWith('ACTION FAILED ')) type = 'action-failed';
    else if (message.startsWith('ACTION ')) type = 'action';
    else if (message.startsWith('USER ACTION ')) type = 'user-action';
    else if (message.startsWith('PROCESS EXITED BY SIGNAL ')) type = 'signal';

    events.push({
      time: timestampMatch ? timestampMatch[1] : '',
      type,
      message,
    });
  }

  return events.reverse();
}

function findProcessByPid(pid) {
  return (latestPayload.processes || []).find((process) => Number(process.pid) === Number(pid)) || null;
}

function buildMarkdownReport(pid) {
  const process = findProcessByPid(pid);
  const timeline = loadTimelineForPid(pid);
  const artifacts = loadRecentSandboxArtifacts().slice(0, 5);
  const lines = [];

  lines.push(`# ProcessGuard Incident Report`);
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`PID: ${pid}`);
  lines.push('');

  if (process) {
    lines.push(`## Current Snapshot`);
    lines.push('');
    lines.push(`- Name: ${process.name}`);
    lines.push(`- Status: ${process.action_label || (process.alerted ? 'ALERT' : 'NORMAL')}`);
    lines.push(`- Alerted: ${process.alerted ? 'yes' : 'no'}`);
    lines.push(`- Score: ${process.alert_score}`);
    lines.push(`- Memory (kB): ${process.memory_kb}`);
    lines.push(`- FD Count: ${process.fd_access_denied ? 'N/A' : process.fd_count}`);
    lines.push(`- CPU Percent: ${process.cpu_percent}`);
    lines.push(`- Threads: ${process.threads}`);
    lines.push(`- Children: ${process.children_count}`);
    lines.push(`- Reason: ${process.alert_reason || 'None'}`);
    lines.push('');
  }

  lines.push(`## Timeline`);
  lines.push('');
  if (timeline.length) {
    for (const event of timeline) {
      lines.push(`- [${event.time}] (${event.type}) ${event.message}`);
    }
  } else {
    lines.push(`- No timeline events recorded for this PID.`);
  }
  lines.push('');

  lines.push(`## Recent Sandbox Artifacts`);
  lines.push('');
  if (artifacts.length) {
    for (const artifact of artifacts) {
      lines.push(`- ${artifact.timestamp}: ${artifact.target} | ${artifact.stage} | ${artifact.status} | peak memory ${artifact.peak_memory_kb} kB`);
    }
  } else {
    lines.push(`- No sandbox artifact records available.`);
  }

  return lines.join('\n');
}

function normalizePayload(payload) {
  const mergedPayload = Array.isArray(payload)
    ? {
        ...latestPayload,
        processes: payload,
        summary: {
          ...latestPayload.summary,
        },
      }
    : {
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
  const snapshotMeta = deriveSnapshotStatus(mergedPayload.generated_at, mergedPayload.scan_interval_seconds);
  const baseProcesses = Array.isArray(mergedPayload.processes) ? mergedPayload.processes : [];
  const liveProcesses = canInspectLinuxProc()
    ? baseProcesses.filter((process) => pidIsLive(Number(process.pid)))
    : baseProcesses;
  const filteredDeadCount = Math.max(0, baseProcesses.length - liveProcesses.length);
  const staleProcessCount = snapshotMeta.status === 'stale' ? liveProcesses.length : 0;
  const exportedProcesses = snapshotMeta.status === 'stale' ? [] : liveProcesses;

  if (Array.isArray(payload)) {
    return {
      ...mergedPayload,
      processes: exportedProcesses,
      summary: {
        ...mergedPayload.summary,
        process_count: exportedProcesses.length,
        alert_count: exportedProcesses.filter((process) => process.alerted).length,
        action_count: exportedProcesses.filter((process) => process.action_taken).length,
        filtered_dead_count: filteredDeadCount,
        stale_process_count: staleProcessCount,
      },
      snapshot_age_seconds: snapshotMeta.ageSeconds,
      snapshot_status: snapshotMeta.status,
    };
  }

  return {
    ...mergedPayload,
    summary: {
      ...mergedPayload.summary,
      process_count: exportedProcesses.length,
      alert_count: exportedProcesses.filter((process) => process.alerted).length,
      action_count: exportedProcesses.filter((process) => process.action_taken).length,
      filtered_dead_count: filteredDeadCount,
      stale_process_count: staleProcessCount,
    },
    processes: exportedProcesses,
    snapshot_age_seconds: snapshotMeta.ageSeconds,
    snapshot_status: snapshotMeta.status,
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

function broadcastSandboxEvents() {
  latestSandboxEvents = loadRecentSandboxEvents();
  io.emit('sandboxEvents', latestSandboxEvents);
}

function broadcastSandboxArtifacts() {
  latestSandboxArtifacts = loadRecentSandboxArtifacts();
  io.emit('sandboxArtifacts', latestSandboxArtifacts);
}

io.on('connection', (socket) => {
  console.log('Frontend dashboard connected');
  socket.emit('processData', loadPayload());
  socket.emit('sandboxEvents', loadRecentSandboxEvents());
  socket.emit('sandboxArtifacts', loadRecentSandboxArtifacts());
});

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    generated_at: latestPayload.generated_at,
    snapshot_status: latestPayload.snapshot_status,
    snapshot_age_seconds: latestPayload.snapshot_age_seconds,
    process_count: latestPayload.summary.process_count,
    alert_count: latestPayload.summary.alert_count,
    action_count: latestPayload.summary.action_count,
  });
});

app.get('/api/sandbox-events', (_req, res) => {
  res.json({
    ok: true,
    events: loadRecentSandboxEvents(),
  });
});

app.get('/api/sandbox-artifacts', (_req, res) => {
  res.json({
    ok: true,
    artifacts: loadRecentSandboxArtifacts(),
  });
});

app.get('/api/timeline/:pid', (req, res) => {
  const pid = Number(req.params.pid);
  if (!Number.isInteger(pid) || pid <= 0) {
    res.status(400).json({ ok: false, error: 'Invalid pid' });
    return;
  }

  res.json({
    ok: true,
    pid,
    events: loadTimelineForPid(pid),
  });
});

app.get('/api/report/:pid', (req, res) => {
  const pid = Number(req.params.pid);
  if (!Number.isInteger(pid) || pid <= 0) {
    res.status(400).json({ ok: false, error: 'Invalid pid' });
    return;
  }

  const format = String(req.query.format || 'md').toLowerCase();
  if (format === 'json') {
    res.json({
      ok: true,
      pid,
      process: findProcessByPid(pid),
      timeline: loadTimelineForPid(pid),
      sandboxArtifacts: loadRecentSandboxArtifacts(),
      generatedAt: new Date().toISOString(),
    });
    return;
  }

  const report = buildMarkdownReport(pid);
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="processguard-report-${pid}.md"`);
  res.send(report);
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
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

  latestPayload = loadPayload();
  const process = findProcessByPid(pid);
  if (!process) {
    res.status(404).json({ ok: false, error: 'PID is not present in the current live snapshot' });
    return;
  }

  if (process.protected_process) {
    res.status(409).json({ ok: false, error: 'Protected system processes cannot be controlled from the dashboard' });
    return;
  }

  fs.appendFileSync(CONTROL_QUEUE_PATH, `${pid} ${action}\n`, 'utf8');
  io.emit('actionQueued', { pid, action });
  res.json({ ok: true, pid, action });
});

latestPayload = loadPayload();
latestSandboxEvents = loadRecentSandboxEvents();
latestSandboxArtifacts = loadRecentSandboxArtifacts();
fs.watchFile(JSON_FILE_PATH, { interval: WATCH_INTERVAL_MS }, broadcastLatestPayload);
fs.watchFile(SANDBOX_EVENTS_PATH, { interval: WATCH_INTERVAL_MS }, broadcastSandboxEvents);
fs.watchFile(SANDBOX_ARTIFACTS_PATH, { interval: WATCH_INTERVAL_MS }, broadcastSandboxArtifacts);

server.on('close', () => {
  fs.unwatchFile(JSON_FILE_PATH, broadcastLatestPayload);
  fs.unwatchFile(SANDBOX_EVENTS_PATH, broadcastSandboxEvents);
  fs.unwatchFile(SANDBOX_ARTIFACTS_PATH, broadcastSandboxArtifacts);
});

const PORT = 3001;
const ALT_PORT = 3002;

function startServer(port) {
  server.listen(port, () => {
    console.log('ProcessGuard Socket.IO server running on port', port);
    console.log('Open dashboard at http://localhost:' + port);
  });
}

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE' && !server.listening) {
    console.error(`Port ${PORT} is already in use.`);
    console.error(`Falling back to port ${ALT_PORT}.`);
    startServer(ALT_PORT);
    return;
  }

  console.error('Server error:', err);
  process.exit(1);
});

startServer(PORT);
