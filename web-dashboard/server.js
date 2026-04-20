const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const JSON_FILE_PATH = path.join(__dirname, '../live_state.json');
const WATCH_INTERVAL_MS = 1000;

let latestPayload = {
    generated_at: null,
    scan_number: 0,
    scan_interval_seconds: 0,
    thresholds: {
        max_memory_kb: 500000,
        max_fd_count: 50,
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
                alert_count: payload.filter((process) => process.memory_kb > latestPayload.thresholds.max_memory_kb || process.fd_count > latestPayload.thresholds.max_fd_count).length,
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
    console.log('Frontend dashboard connected!');
    socket.emit('processData', loadPayload());
});

app.get('/health', (_req, res) => {
    res.json({
        ok: true,
        generated_at: latestPayload.generated_at,
        process_count: latestPayload.summary.process_count,
    });
});

latestPayload = loadPayload();
fs.watchFile(JSON_FILE_PATH, { interval: WATCH_INTERVAL_MS }, broadcastLatestPayload);

server.on('close', () => {
    fs.unwatchFile(JSON_FILE_PATH, broadcastLatestPayload);
});

server.listen(3001, () => {
    console.log('ProcessGuard Socket.io Server running on port 3001');
});
