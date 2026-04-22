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
const RULES_FILE_PATH = path.join(__dirname, '../conf/rules.conf');
const PROCESS_LOG_PATH = path.join(__dirname, '../processguard.log');
const WATCH_INTERVAL_MS = 1000;
const STATIC_DIR = path.join(__dirname, 'public');
const RULE_KEYS = [
  'POLICY_PROFILE',
  'MAX_MEMORY_KB',
  'MAX_FD_COUNT',
  'MAX_SOCKET_COUNT',
  'MAX_THREADS',
  'MAX_CPU_PERCENT',
  'MAX_MEMORY_GROWTH_KB',
  'MAX_FD_GROWTH',
  'MAX_CHILDREN_PER_PPID',
  'MIN_ALERT_SCORE',
  'ALERT_PERSISTENCE_CYCLES',
  'ACTION_MODE',
  'TERMINATE_GRACE_MS',
  'ALLOW_CROSS_UID_ACTION',
  'SANDBOX_MEMORY_KB',
  'SANDBOX_FD_LIMIT',
  'SANDBOX_CPU_SECONDS',
  'SANDBOX_EVAL_SECONDS',
  'SANDBOX_PROMOTE_AFTER_CLEAN',
];
const POLICY_PROFILES = {
  'lab-safe': {
    label: 'Lab Safe',
    description: 'Manual investigation mode. Alerts stay visible and operator approval is required for actions.',
    updates: {
      POLICY_PROFILE: 'lab-safe',
      ACTION_MODE: 'observe',
      ALERT_PERSISTENCE_CYCLES: 1,
      MAX_MEMORY_KB: 98304,
      MAX_FD_COUNT: 36,
      MAX_SOCKET_COUNT: 32,
      MAX_THREADS: 18,
      MAX_CPU_PERCENT: 45,
      MAX_MEMORY_GROWTH_KB: 32768,
      MAX_FD_GROWTH: 12,
      MAX_CHILDREN_PER_PPID: 8,
      MIN_ALERT_SCORE: 40,
      SANDBOX_MEMORY_KB: 131072,
      SANDBOX_FD_LIMIT: 64,
      SANDBOX_CPU_SECONDS: 15,
      SANDBOX_EVAL_SECONDS: 8,
      SANDBOX_PROMOTE_AFTER_CLEAN: 0,
    },
  },
  balanced: {
    label: 'Balanced',
    description: 'Safer auto-response profile for sustained suspicious behavior with a pause-first policy.',
    updates: {
      POLICY_PROFILE: 'balanced',
      ACTION_MODE: 'pause',
      ALERT_PERSISTENCE_CYCLES: 2,
      MAX_MEMORY_KB: 131072,
      MAX_FD_COUNT: 48,
      MAX_SOCKET_COUNT: 40,
      MAX_THREADS: 24,
      MAX_CPU_PERCENT: 60,
      MAX_MEMORY_GROWTH_KB: 49152,
      MAX_FD_GROWTH: 16,
      MAX_CHILDREN_PER_PPID: 10,
      MIN_ALERT_SCORE: 50,
      SANDBOX_MEMORY_KB: 131072,
      SANDBOX_FD_LIMIT: 64,
      SANDBOX_CPU_SECONDS: 15,
      SANDBOX_EVAL_SECONDS: 8,
      SANDBOX_PROMOTE_AFTER_CLEAN: 0,
    },
  },
  strict: {
    label: 'Strict',
    description: 'Aggressive policy for high-risk lab scenarios with lower thresholds and terminate-first response.',
    updates: {
      POLICY_PROFILE: 'strict',
      ACTION_MODE: 'terminate',
      ALERT_PERSISTENCE_CYCLES: 1,
      MAX_MEMORY_KB: 65536,
      MAX_FD_COUNT: 24,
      MAX_SOCKET_COUNT: 24,
      MAX_THREADS: 12,
      MAX_CPU_PERCENT: 35,
      MAX_MEMORY_GROWTH_KB: 16384,
      MAX_FD_GROWTH: 8,
      MAX_CHILDREN_PER_PPID: 5,
      MIN_ALERT_SCORE: 35,
      SANDBOX_MEMORY_KB: 98304,
      SANDBOX_FD_LIMIT: 48,
      SANDBOX_CPU_SECONDS: 10,
      SANDBOX_EVAL_SECONDS: 6,
      SANDBOX_PROMOTE_AFTER_CLEAN: 0,
    },
  },
};

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
  },
  processes: [],
};
let latestSandboxEvents = [];
let latestSandboxArtifacts = [];

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

function parseRulesFile() {
  if (!fs.existsSync(RULES_FILE_PATH)) {
    return {};
  }

  const result = {};
  const lines = fs.readFileSync(RULES_FILE_PATH, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) {
      continue;
    }

    const separatorIndex = trimmed.indexOf('=');
    const key = trimmed.slice(0, separatorIndex);
    const value = trimmed.slice(separatorIndex + 1);
    result[key] = value;
  }

  return result;
}

function getPolicyProfilePayload() {
  const rules = parseRulesFile();
  const active = rules.POLICY_PROFILE || 'custom';
  return {
    active,
    restartRequired: true,
    profiles: Object.entries(POLICY_PROFILES).map(([name, profile]) => ({
      name,
      label: profile.label,
      description: profile.description,
      actionMode: profile.updates.ACTION_MODE,
      minAlertScore: Number(profile.updates.MIN_ALERT_SCORE),
      persistence: Number(profile.updates.ALERT_PERSISTENCE_CYCLES),
      thresholds: {
        memoryKb: Number(profile.updates.MAX_MEMORY_KB),
        fdCount: Number(profile.updates.MAX_FD_COUNT),
        sockets: Number(profile.updates.MAX_SOCKET_COUNT),
        threads: Number(profile.updates.MAX_THREADS),
        cpuPercent: Number(profile.updates.MAX_CPU_PERCENT),
      },
    })),
    currentRules: rules,
  };
}

function applyPolicyProfile(profileName) {
  const profile = POLICY_PROFILES[profileName];
  if (!profile) {
    return false;
  }

  const existingLines = fs.existsSync(RULES_FILE_PATH)
    ? fs.readFileSync(RULES_FILE_PATH, 'utf8').split(/\r?\n/)
    : [];
  const pendingKeys = new Set(RULE_KEYS);
  const nextLines = existingLines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) {
      return line;
    }

    const separatorIndex = trimmed.indexOf('=');
    const key = trimmed.slice(0, separatorIndex);
    if (!(key in profile.updates)) {
      return line;
    }

    pendingKeys.delete(key);
    return `${key}=${profile.updates[key]}`;
  });

  for (const key of pendingKeys) {
    if (key in profile.updates) {
      nextLines.push(`${key}=${profile.updates[key]}`);
    }
  }

  fs.writeFileSync(RULES_FILE_PATH, `${nextLines.join('\n').trim()}\n`, 'utf8');
  return true;
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

app.get('/api/policy-profiles', (_req, res) => {
  res.json({
    ok: true,
    ...getPolicyProfilePayload(),
  });
});

app.post('/api/policy-profiles/:name', (req, res) => {
  const name = String(req.params.name || '').trim().toLowerCase();
  if (!applyPolicyProfile(name)) {
    res.status(404).json({ ok: false, error: 'Unknown profile' });
    return;
  }

  res.json({
    ok: true,
    message: 'Profile written to conf/rules.conf. Restart the monitor to apply it.',
    ...getPolicyProfilePayload(),
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
