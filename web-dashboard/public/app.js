(function () {
  const state = {
    processes: [],
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
    generatedAt: null,
    scanNumber: 0,
    scanIntervalSeconds: 0,
    lastUpdated: null,
    search: '',
    sortKey: 'memory_kb',
    sortDir: 'desc',
    pendingActions: {},
    queuedActions: {},
    sandboxEvents: [],
    sandboxArtifacts: [],
    selectedPid: null,
    timelineEvents: [],
    policyProfiles: null,
    profileMessage: '',
  };

  const statsGrid = document.getElementById('statsGrid');
  const tableBody = document.getElementById('processTableBody');
  const metaInfo = document.getElementById('metaInfo');
  const tableSummary = document.getElementById('tableSummary');
  const searchInput = document.getElementById('searchInput');
  const connectionStatus = document.getElementById('connectionStatus');
  const lastUpdated = document.getElementById('lastUpdated');
  const sandboxEvents = document.getElementById('sandboxEvents');
  const sandboxSummary = document.getElementById('sandboxSummary');
  const sandboxLatest = document.getElementById('sandboxLatest');
  const explainabilityPanel = document.getElementById('explainabilityPanel');
  const timelinePanel = document.getElementById('timelinePanel');
  const processTreePanel = document.getElementById('processTreePanel');
  const policyProfilesPanel = document.getElementById('policyProfilesPanel');
  const sortHeaders = document.querySelectorAll('th[data-sort]');

  function formatMemory(kb) {
    if (kb >= 1048576) return (kb / 1048576).toFixed(1) + ' GB';
    if (kb >= 1024) return (kb / 1024).toFixed(1) + ' MB';
    return kb + ' KB';
  }

  function formatRuntime(seconds) {
    if (!seconds || seconds < 0) return '0s';
    if (seconds >= 3600) return (seconds / 3600).toFixed(1) + 'h';
    if (seconds >= 60) return (seconds / 60).toFixed(1) + 'm';
    return seconds.toFixed(1) + 's';
  }

  function formatSignedKb(kb) {
    if (kb > 0) return '+' + Number(kb).toLocaleString() + ' kB';
    if (kb < 0) return Number(kb).toLocaleString() + ' kB';
    return '0 kB';
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function normalizeProcesses(processes, thresholds) {
    return (processes || []).map(function (process) {
      const memoryKb = Number(process.memory_kb || 0);
      const fdCount = Number(process.fd_count || 0);
      const memoryAlert = typeof process.memory_alert === 'boolean' ? process.memory_alert : memoryKb > thresholds.max_memory_kb;
      const fdAlert = typeof process.fd_alert === 'boolean' ? process.fd_alert : fdCount > thresholds.max_fd_count;
      const alerted = typeof process.alerted === 'boolean' ? process.alerted : memoryAlert || fdAlert;

      return {
        pid: Number(process.pid || 0),
        ppid: Number(process.ppid || 0),
        name: process.name || 'Unknown',
        state: process.state || '',
        memory_kb: memoryKb,
        memory_delta_kb: Number(process.memory_delta_kb || 0),
        fd_count: fdCount,
        fd_access_denied: Boolean(process.fd_access_denied),
        socket_count: Number(process.socket_count || 0),
        threads: Number(process.threads || 0),
        children_count: Number(process.children_count || 0),
        cpu_percent: Number(process.cpu_percent || 0),
        runtime_seconds: Number(process.runtime_seconds || 0),
        sustained_alerts: Number(process.sustained_alerts || 0),
        alert_score: Number(process.alert_score || 0),
        action_taken: Boolean(process.action_taken),
        protected_process: Boolean(process.protected_process),
        user_allowed: Boolean(process.user_allowed),
        simulation_match: Boolean(process.simulation_match),
        category: process.category || '',
        action_label: process.action_label || '',
        alert_reason: process.alert_reason || '',
        alerted: alerted,
        memory_alert: memoryAlert,
        fd_alert: fdAlert,
        socket_alert: Boolean(process.socket_alert),
        thread_alert: Boolean(process.thread_alert),
        cpu_alert: Boolean(process.cpu_alert),
        growth_alert: Boolean(process.growth_alert),
        fork_alert: Boolean(process.fork_alert),
      };
    });
  }

  function normalizePayload(payload) {
    const thresholds = Object.assign({}, state.thresholds, payload && payload.thresholds ? payload.thresholds : {});
    const processes = normalizeProcesses(payload && Array.isArray(payload.processes) ? payload.processes : Array.isArray(payload) ? payload : [], thresholds);
    const summary = Object.assign({}, state.summary, payload && payload.summary ? payload.summary : {});

    return {
      thresholds: thresholds,
      processes: processes,
      summary: Object.assign(summary, {
        process_count: summary.process_count || processes.length,
        alert_count: typeof summary.alert_count === 'number' ? summary.alert_count : processes.filter(function (process) { return process.alerted; }).length,
      }),
      generatedAt: payload && payload.generated_at ? payload.generated_at : null,
      scanNumber: payload && payload.scan_number ? payload.scan_number : 0,
      scanIntervalSeconds: payload && payload.scan_interval_seconds ? payload.scan_interval_seconds : 0,
      lastUpdated: new Date(),
    };
  }

  function getSelectedProcess() {
    if (state.selectedPid == null) {
      return null;
    }

    for (let i = 0; i < state.processes.length; i += 1) {
      if (state.processes[i].pid === state.selectedPid) {
        return state.processes[i];
      }
    }

    return null;
  }

  function getStatusInfo(process) {
    if (process.protected_process) {
      return { label: 'PROTECTED', className: 'status-protected' };
    }

    switch (process.action_label) {
      case 'PAUSED':
      case 'FAMILY_ACTION':
        return { label: 'PAUSED', className: 'status-paused' };
      case 'USER_ALLOWED':
        return { label: 'CONTINUED', className: 'status-continued' };
      case 'TERMINATED':
        return { label: 'STOPPED', className: 'status-stopped' };
      case 'KILLED':
        return { label: 'KILLED', className: 'status-killed' };
      case 'SKIPPED_PROTECTED':
        return { label: 'PROTECTED', className: 'status-protected' };
      case 'OBSERVE':
        return { label: 'ALERT', className: 'status-alert' };
      case 'ACTION_FAILED':
        return { label: 'ACTION FAILED', className: 'status-killed' };
      default:
        if (process.alerted) {
          return {
            label: process.action_taken ? 'PAUSED' : 'ALERT',
            className: process.action_taken ? 'status-paused' : 'status-alert',
          };
        }

        return { label: 'NORMAL', className: 'status-normal' };
    }
  }

  function getRiskBand(score, alerted) {
    if (!alerted) return { label: 'Normal / Below Threshold', className: 'band-normal', color: 'var(--green)' };
    if (score >= 90) return { label: 'High Severity', className: 'band-high', color: 'var(--red)' };
    if (score >= 60) return { label: 'Medium Severity', className: 'band-medium', color: '#fb923c' };
    return { label: 'Low Severity', className: 'band-low', color: 'var(--yellow)' };
  }

  function shouldShowActions(process) {
    return Boolean(process.alerted && !process.protected_process);
  }

  function renderStats() {
    const totalMemory = state.processes.reduce(function (sum, process) { return sum + process.memory_kb; }, 0);
    const totalFds = state.processes.reduce(function (sum, process) { return sum + process.fd_count; }, 0);
    const cards = [
      ['Processes', String(state.summary.process_count || state.processes.length), '#22d3ee'],
      ['Total Memory', formatMemory(totalMemory), '#4ade80'],
      ['Total FDs', String(totalFds), '#60a5fa'],
      ['Alerts', String(state.summary.alert_count || 0), state.summary.alert_count > 0 ? '#f87171' : '#94a3b8'],
    ];

    statsGrid.innerHTML = cards.map(function (card) {
      return '<div class="stat-card">' +
        '<div class="stat-label">' + card[0] + '</div>' +
        '<div class="stat-value" style="color:' + card[2] + '">' + card[1] + '</div>' +
      '</div>';
    }).join('');
  }

  function renderMeta() {
    const meta = [
      'Scan #' + (state.scanNumber || 0),
      'Interval: ' + (state.scanIntervalSeconds || 0) + 's',
      'Mem Limit: ' + Number(state.thresholds.max_memory_kb || 0).toLocaleString() + ' kB',
      'FD Limit: ' + (state.thresholds.max_fd_count || 0),
      'FD Limited: ' + (state.summary.fd_access_limited_count || 0),
    ];
    if (state.generatedAt) {
      meta.push('Snapshot: ' + new Date(state.generatedAt).toLocaleTimeString());
    }

    metaInfo.innerHTML = meta.map(function (item) { return '<span>' + item + '</span>'; }).join('');
    lastUpdated.textContent = state.lastUpdated ? 'Last update: ' + state.lastUpdated.toLocaleTimeString() : '';
  }

  function getVisibleProcesses() {
    const search = state.search.trim().toLowerCase();
    const filtered = search
      ? state.processes.filter(function (process) {
          return process.name.toLowerCase().indexOf(search) !== -1 || String(process.pid).indexOf(search) !== -1;
        })
      : state.processes.slice();

    return filtered.sort(function (a, b) {
      const av = a[state.sortKey];
      const bv = b[state.sortKey];
      if (typeof av === 'string' && typeof bv === 'string') {
        return state.sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
      }
      return state.sortDir === 'asc' ? Number(av) - Number(bv) : Number(bv) - Number(av);
    });
  }

  function renderActions(pid, pendingAction, queuedAction) {
    const actions = [
      ['continue', 'Continue', 'action-continue'],
      ['pause', 'Pause', 'action-pause'],
      ['stop', 'Stop', 'action-stop'],
      ['kill', 'Kill', 'action-kill'],
    ];

    const buttons = actions.map(function (action) {
      const disabled = pendingAction ? 'disabled' : '';
      const label = pendingAction === action[0] ? 'Sending...' : action[1];
      return '<button class="action-btn ' + action[2] + '" data-action="' + action[0] + '" data-pid="' + pid + '" ' + disabled + '>' + label + '</button>';
    }).join('');

    const note = queuedAction
      ? '<div class="queued-note">Last queued action: ' + escapeHtml(queuedAction) + '</div>'
      : '';

    return '<div class="action-group">' + buttons + '</div>' + note;
  }

  function renderTable() {
    const rows = getVisibleProcesses();
    const alertCount = state.processes.filter(function (process) { return process.alerted; }).length;
    tableSummary.textContent = rows.length + ' processes' + (alertCount ? ' | ' + alertCount + ' alerts' : '');

    if (!rows.length) {
      tableBody.innerHTML = '<tr><td colspan="6" class="empty-state">' +
        (state.processes.length ? 'No matching processes' : 'Waiting for data...') +
      '</td></tr>';
      return;
    }

    tableBody.innerHTML = rows.map(function (process) {
      const memoryClass = process.memory_alert ? 'memory-alert' : 'memory-ok';
      const fdClass = process.fd_alert ? 'fd-alert' : 'fd-ok';
      const fdValue = process.fd_access_denied ? 'N/A' : process.fd_count;
      const pendingAction = state.pendingActions[process.pid];
      const queuedAction = state.queuedActions[process.pid];
      const statusInfo = getStatusInfo(process);
      const actionsHtml = shouldShowActions(process)
        ? renderActions(process.pid, pendingAction, queuedAction)
        : '<span class="status-muted">No manual action</span>';
      const rowClasses = [
        process.alerted ? 'row-alert' : '',
        state.selectedPid === process.pid ? 'row-selected' : '',
      ].filter(Boolean).join(' ');

      return '<tr class="' + rowClasses + '" data-select-pid="' + process.pid + '">' +
        '<td>' + process.pid + '</td>' +
        '<td>' + escapeHtml(process.name) + '</td>' +
        '<td class="' + memoryClass + '">' + formatMemory(process.memory_kb) + '</td>' +
        '<td class="' + fdClass + '">' + fdValue + '</td>' +
        '<td class="' + statusInfo.className + '" title="' + escapeHtml(process.alert_reason || process.action_label || '') + '">' + statusInfo.label + '</td>' +
        '<td class="actions-cell">' + actionsHtml + '</td>' +
      '</tr>';
    }).join('');
  }

  function renderMetric(label, value, color) {
    return '<div class="explain-metric">' +
      '<div class="explain-metric-label">' + label + '</div>' +
      '<div class="explain-metric-value" style="color:' + color + '">' + value + '</div>' +
    '</div>';
  }

  function renderList(items, emptyMessage) {
    if (!items.length) {
      return '<div class="empty-state">' + emptyMessage + '</div>';
    }

    return '<ul class="explain-list">' + items.map(function (item) {
      return '<li class="explain-list-item">' +
        '<div class="explain-list-head">' +
          '<div class="explain-list-title">' + escapeHtml(item.title) + '</div>' +
          '<div class="explain-list-badge">' + escapeHtml(item.badge) + '</div>' +
        '</div>' +
        '<div class="explain-list-body">' + escapeHtml(item.body) + '</div>' +
      '</li>';
    }).join('') + '</ul>';
  }

  function getTriggerDetails(process) {
    const items = [];
    if (process.memory_alert) {
      items.push({ title: 'Memory threshold exceeded', badge: '+40', body: 'Resident memory is ' + formatMemory(process.memory_kb) + ', above the configured threshold of ' + Number(state.thresholds.max_memory_kb || 0).toLocaleString() + ' kB.' });
    }
    if (process.fd_alert) {
      items.push({ title: 'File descriptor threshold exceeded', badge: '+25', body: 'The process has ' + process.fd_count + ' open descriptors, above the configured limit of ' + (state.thresholds.max_fd_count || 0) + '.' });
    }
    if (process.socket_alert) {
      items.push({ title: 'Socket activity exceeded threshold', badge: '+20', body: 'Socket count reached ' + process.socket_count + ', indicating broad network or IPC activity for a single process.' });
    }
    if (process.thread_alert) {
      items.push({ title: 'Thread count exceeded threshold', badge: '+20', body: 'Thread count reached ' + process.threads + ', which is above the configured maximum and may indicate runaway concurrency.' });
    }
    if (process.cpu_alert) {
      items.push({ title: 'CPU usage exceeded threshold', badge: '+20', body: 'CPU usage is ' + process.cpu_percent.toFixed(1) + '%, higher than the configured threshold for a sustained process sample.' });
    }
    if (process.growth_alert) {
      items.push({ title: 'Rapid growth detected', badge: '+15 / +20', body: 'The process showed unusual growth between scans, including memory delta ' + formatSignedKb(process.memory_delta_kb) + '.' });
    }
    if (process.fork_alert) {
      items.push({ title: 'Excessive child-process fan-out', badge: '+35', body: 'This process currently owns ' + process.children_count + ' children, which is treated as suspicious process-family expansion.' });
    }
    if (process.simulation_match) {
      items.push({ title: 'Bundled simulator signature matched', badge: '+60', body: 'The process name or command line matches one of the built-in simulator signatures used for demonstration and testing.' });
    }
    return items;
  }

  function getObservationDetails(process) {
    const items = [
      { title: 'Current control posture', badge: 'Status', body: 'The monitor currently labels this process as ' + getStatusInfo(process).label + '. This reflects detection state plus any manual or automatic action already taken.' },
      { title: 'Alert persistence', badge: 'Timing', body: 'The process has sustained ' + process.sustained_alerts + ' alert cycles. Repeated triggers across scans help separate spikes from persistent suspicious behavior.' },
    ];

    if (process.protected_process) {
      items.push({ title: 'Protected-process safeguard', badge: 'Safety', body: 'Even though this process matched alert rules, ProcessGuard marked it as protected and intentionally withheld manual controls to avoid harming the system.' });
    }
    if (process.user_allowed) {
      items.push({ title: 'User-approved continuation', badge: 'Operator', body: 'This PID has been explicitly continued by the operator, so the monitor preserves visibility while avoiding repeated automatic intervention.' });
    }
    if (process.fd_access_denied) {
      items.push({ title: 'Limited file-descriptor visibility', badge: 'Permissions', body: 'FD enumeration was permission-limited for this process, so the monitor used partial telemetry and clearly marked the missing field as unavailable.' });
    }
    if (process.category) {
      items.push({ title: 'Process category', badge: 'Context', body: 'This process is categorized as ' + process.category + ', which can help distinguish demonstrations, suspicious behaviors, and ordinary host workloads.' });
    }
    return items;
  }

  function renderExplainability() {
    const selectedProcess = getSelectedProcess();
    if (!selectedProcess) {
      explainabilityPanel.innerHTML = '<div class="empty-state">Select a process row to inspect its risk breakdown.</div>';
      return;
    }

    const statusInfo = getStatusInfo(selectedProcess);
    const band = getRiskBand(selectedProcess.alert_score, selectedProcess.alerted);
    const triggers = getTriggerDetails(selectedProcess);
    const observations = getObservationDetails(selectedProcess);

    explainabilityPanel.innerHTML =
      '<div class="explain-top">' +
        '<div class="explain-section">' +
          '<div class="explain-kicker">Selected Process</div>' +
          '<div class="explain-title">' + escapeHtml(selectedProcess.name) + ' <span class="status-muted">#' + selectedProcess.pid + '</span></div>' +
          '<div class="explain-subtitle">' + escapeHtml(selectedProcess.category || 'general process') + ' | parent PID ' + selectedProcess.ppid + ' | state ' + escapeHtml(selectedProcess.state || 'unknown') + '</div>' +
          '<div class="explain-status ' + statusInfo.className + '">' + escapeHtml(statusInfo.label) + '</div>' +
          '<div class="explain-actions">' +
            '<button class="panel-btn panel-btn-primary" data-report="md" data-report-pid="' + selectedProcess.pid + '">Export Markdown Report</button>' +
            '<button class="panel-btn" data-report="json" data-report-pid="' + selectedProcess.pid + '">Open JSON Report</button>' +
          '</div>' +
          '<div class="explain-grid">' +
            renderMetric('Memory', formatMemory(selectedProcess.memory_kb), selectedProcess.memory_alert ? 'var(--red)' : 'var(--green)') +
            renderMetric('FD Count', selectedProcess.fd_access_denied ? 'N/A' : String(selectedProcess.fd_count), selectedProcess.fd_alert ? 'var(--red)' : 'var(--cyan)') +
            renderMetric('CPU', selectedProcess.cpu_percent.toFixed(1) + '%', selectedProcess.cpu_alert ? '#fb923c' : 'var(--text)') +
            renderMetric('Sockets', String(selectedProcess.socket_count), selectedProcess.socket_alert ? 'var(--red)' : 'var(--text)') +
            renderMetric('Threads', String(selectedProcess.threads), selectedProcess.thread_alert ? 'var(--red)' : 'var(--text)') +
            renderMetric('Children', String(selectedProcess.children_count), selectedProcess.fork_alert ? 'var(--red)' : 'var(--text)') +
          '</div>' +
        '</div>' +
        '<div class="explain-section">' +
          '<div class="explain-kicker">Risk Summary</div>' +
          '<div class="risk-score">' +
            '<div class="risk-score-value" style="color:' + band.color + '">' + selectedProcess.alert_score + '</div>' +
            '<div class="risk-score-label">score across active detection signals</div>' +
          '</div>' +
          '<div class="risk-band ' + band.className + '">' + band.label + '</div>' +
          '<div class="explain-subtitle">Sustained alerts: ' + selectedProcess.sustained_alerts + ' | runtime: ' + formatRuntime(selectedProcess.runtime_seconds) + ' | memory growth: ' + formatSignedKb(selectedProcess.memory_delta_kb) + '</div>' +
          '<div class="explain-subtitle" style="margin-top:14px;">' + escapeHtml(selectedProcess.alert_reason || 'No explicit alert reason recorded.') + '</div>' +
        '</div>' +
      '</div>' +
      '<div class="explain-bottom">' +
        '<div class="explain-section">' +
          '<div class="explain-kicker">Triggered Signals</div>' +
          renderList(triggers, 'No detection rules triggered for this process in the current snapshot.') +
        '</div>' +
        '<div class="explain-section">' +
          '<div class="explain-kicker">Context And Interpretation</div>' +
          renderList(observations, 'No extra context available.') +
        '</div>' +
      '</div>';
  }

  function renderSandboxEvents() {
    if (!state.sandboxEvents.length) {
      sandboxSummary.innerHTML = '<div class="empty-state">No sandbox summary yet.</div>';
      sandboxLatest.innerHTML = '<div class="empty-state">Run `./processguard &lt;command&gt;` to review a command in the sandbox.</div>';
      sandboxEvents.innerHTML = '<div class="empty-state">No sandbox events yet.</div>';
      return;
    }

    renderSandboxOverview();
    sandboxEvents.innerHTML = state.sandboxEvents.map(function (event) {
      const status = String(event.status || 'unknown');
      const timestamp = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '--';
      return '<div class="sandbox-event">' +
        '<div class="sandbox-time">' + escapeHtml(timestamp) + '</div>' +
        '<div class="sandbox-stage">' + escapeHtml(event.stage || 'review') + '</div>' +
        '<div class="sandbox-status sandbox-status-' + escapeHtml(status) + '">' + escapeHtml(status.toUpperCase()) + '</div>' +
        '<div class="sandbox-target">' + escapeHtml(event.target || 'sandbox') + '</div>' +
        '<div><div class="status-muted">' + escapeHtml(event.detail || '') + '</div></div>' +
      '</div>';
    }).join('');
  }

  function renderSandboxOverview() {
    const counts = { total: state.sandboxEvents.length, blocked: 0, clean: 0, failed: 0, commands: new Set() };
    state.sandboxEvents.forEach(function (event) {
      const status = String(event.status || '').toLowerCase();
      if (status === 'blocked') counts.blocked += 1;
      if (status === 'clean' || status === 'completed') counts.clean += 1;
      if (status === 'failed' || status === 'interrupted') counts.failed += 1;
      if (event.target && event.target !== 'sandbox-group') counts.commands.add(event.target);
    });

    const summaryCards = [
      ['Events', String(counts.total), '#22d3ee'],
      ['Commands', String(counts.commands.size), '#60a5fa'],
      ['Blocked', String(counts.blocked), counts.blocked ? '#f87171' : '#94a3b8'],
      ['Clean', String(counts.clean), counts.clean ? '#4ade80' : '#94a3b8'],
    ];

    sandboxSummary.innerHTML = '<div class="sandbox-summary-grid">' + summaryCards.map(function (card) {
      return '<div class="sandbox-summary-item">' +
        '<div class="sandbox-summary-label">' + card[0] + '</div>' +
        '<div class="sandbox-summary-value" style="color:' + card[2] + '">' + card[1] + '</div>' +
      '</div>';
    }).join('') + '</div>';

    const latestEvent = state.sandboxEvents[0];
    const latestArtifact = state.sandboxArtifacts[0];
    const latestStatus = String(latestEvent.status || 'unknown');
    const latestTime = latestEvent.timestamp ? new Date(latestEvent.timestamp).toLocaleString() : '--';
    const artifactMeta = latestArtifact
      ? '<div class="sandbox-latest-meta">' +
          '<span>Peak memory: ' + escapeHtml(String(latestArtifact.peak_memory_kb || 0)) + ' kB</span>' +
          '<span>Peak FDs: ' + escapeHtml(String(latestArtifact.peak_fd_count || 0)) + '</span>' +
          '<span>Peak threads: ' + escapeHtml(String(latestArtifact.peak_threads || 0)) + '</span>' +
          '<span>Runtime: ' + escapeHtml(String(latestArtifact.runtime_seconds || 0)) + 's</span>' +
        '</div>'
      : '';
    const artifactLinks = latestArtifact
      ? '<div class="sandbox-artifact-links">' +
          (latestArtifact.stdout_href ? '<a class="artifact-link" target="_blank" href="' + escapeHtml(latestArtifact.stdout_href) + '">stdout</a>' : '') +
          (latestArtifact.stderr_href ? '<a class="artifact-link" target="_blank" href="' + escapeHtml(latestArtifact.stderr_href) + '">stderr</a>' : '') +
        '</div>'
      : '';

    sandboxLatest.innerHTML =
      '<div class="sandbox-latest-label">Latest Verdict</div>' +
      '<div class="sandbox-latest-status sandbox-status-' + escapeHtml(latestStatus) + '">' + escapeHtml(latestStatus.toUpperCase()) + '</div>' +
      '<div class="sandbox-latest-target">' + escapeHtml(latestEvent.target || 'sandbox') + '</div>' +
      '<div class="sandbox-latest-detail">' + escapeHtml(latestEvent.detail || 'No additional detail') + '</div>' +
      '<div class="sandbox-latest-meta">' +
        '<span>Stage: ' + escapeHtml(latestEvent.stage || 'review') + '</span>' +
        '<span>Seen: ' + escapeHtml(latestTime) + '</span>' +
      '</div>' +
      artifactMeta +
      artifactLinks;
  }

  function renderTimeline() {
    if (state.selectedPid == null) {
      timelinePanel.innerHTML = '<div class="empty-state">Select a process to inspect its incident timeline.</div>';
      return;
    }
    if (!state.timelineEvents.length) {
      timelinePanel.innerHTML = '<div class="empty-state">No timeline events recorded yet for PID ' + state.selectedPid + '.</div>';
      return;
    }

    timelinePanel.innerHTML = '<div class="timeline-list">' + state.timelineEvents.map(function (event) {
      return '<div class="timeline-item">' +
        '<div class="timeline-head">' +
          '<div class="timeline-type">' + escapeHtml(event.type || 'log') + '</div>' +
          '<div class="timeline-time">' + escapeHtml(event.time || '--') + '</div>' +
        '</div>' +
        '<div class="timeline-body">' + escapeHtml(event.message || '') + '</div>' +
      '</div>';
    }).join('') + '</div>';
  }

  function renderTreeNodes(nodes, emptyMessage) {
    if (!nodes.length) {
      return '<div class="empty-state">' + emptyMessage + '</div>';
    }

    return '<div class="tree-list">' + nodes.map(function (node) {
      const process = node.process;
      return '<div class="tree-item tree-node" style="--tree-depth:' + node.depth + '">' +
        '<div class="tree-head">' +
          '<div>' + escapeHtml(process.name) + ' <span class="status-muted">#' + process.pid + '</span></div>' +
          '<div class="tree-meta">' + escapeHtml(getStatusInfo(process).label) + '</div>' +
        '</div>' +
        '<div class="tree-body">ppid ' + process.ppid + ' | mem ' + formatMemory(process.memory_kb) + ' | fd ' + (process.fd_access_denied ? 'N/A' : process.fd_count) + '</div>' +
      '</div>';
    }).join('') + '</div>';
  }

  function renderProcessTree() {
    const selectedProcess = getSelectedProcess();
    if (!selectedProcess) {
      processTreePanel.innerHTML = '<div class="empty-state">Select a process to inspect its process tree.</div>';
      return;
    }

    const processMap = new Map();
    state.processes.forEach(function (process) { processMap.set(process.pid, process); });

    const ancestry = [];
    let cursor = selectedProcess;
    while (cursor) {
      ancestry.unshift(cursor);
      cursor = processMap.get(cursor.ppid) || null;
    }

    const descendants = [];
    function collectDescendants(pid, depth) {
      state.processes
        .filter(function (process) { return process.ppid === pid; })
        .sort(function (a, b) { return a.pid - b.pid; })
        .forEach(function (child) {
          descendants.push({ process: child, depth: depth });
          collectDescendants(child.pid, depth + 1);
        });
    }
    collectDescendants(selectedProcess.pid, 0);

    processTreePanel.innerHTML =
      '<div class="tree-group">' +
        '<div class="tree-column">' +
          '<div class="tree-column-title">Ancestor Chain</div>' +
          renderTreeNodes(ancestry.map(function (process, index) { return { process: process, depth: index }; }), 'No ancestors found.') +
        '</div>' +
        '<div class="tree-column">' +
          '<div class="tree-column-title">Descendants</div>' +
          renderTreeNodes(descendants, 'No child processes in the current snapshot.') +
        '</div>' +
      '</div>';
  }

  function renderProfileStat(label, value) {
    return '<div class="profile-stat">' +
      '<div class="profile-stat-label">' + escapeHtml(label) + '</div>' +
      '<div class="profile-stat-value">' + escapeHtml(value) + '</div>' +
    '</div>';
  }

  function renderPolicyProfiles() {
    if (!state.policyProfiles) {
      policyProfilesPanel.innerHTML = '<div class="empty-state">Loading policy profiles...</div>';
      return;
    }

    const active = state.policyProfiles.active || 'custom';
    const topMessage = state.profileMessage
      ? '<div class="profile-card"><div class="profile-desc">' + escapeHtml(state.profileMessage) + '</div></div>'
      : '';

    const cards = state.policyProfiles.profiles.map(function (profile) {
      const isActive = active === profile.name;
      return '<div class="profile-card ' + (isActive ? 'profile-card-active' : '') + '">' +
        '<div class="profile-title-row">' +
          '<div class="profile-title">' + escapeHtml(profile.label) + '</div>' +
          (isActive ? '<div class="profile-badge">Active</div>' : '') +
        '</div>' +
        '<div class="profile-desc">' + escapeHtml(profile.description) + '</div>' +
        '<div class="profile-stats">' +
          renderProfileStat('Action', profile.actionMode) +
          renderProfileStat('Persistence', String(profile.persistence)) +
          renderProfileStat('Min Score', String(profile.minAlertScore)) +
          renderProfileStat('CPU', String(profile.thresholds.cpuPercent) + '%') +
        '</div>' +
        '<div class="profile-note">Applying a profile writes to conf/rules.conf. Restart ./processguard after changing it.</div>' +
        '<div class="explain-actions">' +
          '<button class="panel-btn ' + (isActive ? '' : 'panel-btn-primary') + '" data-policy-profile="' + profile.name + '">' + (isActive ? 'Applied' : 'Apply Profile') + '</button>' +
        '</div>' +
      '</div>';
    }).join('');

    policyProfilesPanel.innerHTML = topMessage + cards;
  }

  function render() {
    renderStats();
    renderMeta();
    renderTable();
    renderSandboxEvents();
    renderExplainability();
    renderTimeline();
    renderProcessTree();
    renderPolicyProfiles();
  }

  async function queueAction(pid, action) {
    state.pendingActions[pid] = action;
    renderTable();

    try {
      const response = await fetch('/api/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pid, action: action }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) {
        throw new Error(payload && payload.error ? payload.error : 'Failed to queue action');
      }
      state.queuedActions[pid] = action;
    } catch (error) {
      window.alert('Could not queue action for PID ' + pid + ': ' + error.message);
    } finally {
      delete state.pendingActions[pid];
      renderTable();
    }
  }

  async function refreshTimeline() {
    if (state.selectedPid == null) {
      state.timelineEvents = [];
      renderTimeline();
      return;
    }
    try {
      const response = await fetch('/api/timeline/' + state.selectedPid);
      const payload = await response.json();
      state.timelineEvents = payload.ok && Array.isArray(payload.events) ? payload.events : [];
    } catch (_error) {
      state.timelineEvents = [];
    }
    renderTimeline();
  }

  async function refreshPolicyProfiles(message) {
    try {
      const response = await fetch('/api/policy-profiles');
      const payload = await response.json();
      if (payload.ok) {
        state.policyProfiles = payload;
        state.profileMessage = message || '';
      }
    } catch (_error) {
      state.profileMessage = 'Could not load policy profiles.';
    }
    renderPolicyProfiles();
  }

  async function applyPolicyProfile(profileName) {
    try {
      const response = await fetch('/api/policy-profiles/' + encodeURIComponent(profileName), { method: 'POST' });
      const payload = await response.json();
      if (!response.ok || !payload.ok) {
        throw new Error(payload && payload.error ? payload.error : 'Failed to apply profile');
      }
      state.policyProfiles = payload;
      state.profileMessage = payload.message || 'Profile updated.';
    } catch (error) {
      state.profileMessage = 'Could not apply profile: ' + error.message;
    }
    renderPolicyProfiles();
  }

  function setConnectionStatus(status, label) {
    connectionStatus.className = 'status status-' + status;
    connectionStatus.textContent = label;
  }

  searchInput.addEventListener('input', function (event) {
    state.search = event.target.value || '';
    renderTable();
  });

  sortHeaders.forEach(function (header) {
    header.addEventListener('click', function () {
      const nextKey = header.getAttribute('data-sort');
      if (!nextKey) return;
      if (state.sortKey === nextKey) {
        state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        state.sortKey = nextKey;
        state.sortDir = 'desc';
      }
      renderTable();
    });
  });

  tableBody.addEventListener('click', function (event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    const row = target.closest('tr[data-select-pid]');
    if (row) {
      state.selectedPid = Number(row.getAttribute('data-select-pid'));
      render();
      refreshTimeline();
    }

    const action = target.getAttribute('data-action');
    const pidText = target.getAttribute('data-pid');
    if (!action || !pidText) {
      return;
    }

    const pid = Number(pidText);
    if (!pid) {
      return;
    }

    queueAction(pid, action);
  });

  explainabilityPanel.addEventListener('click', function (event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    const pid = target.getAttribute('data-report-pid');
    const format = target.getAttribute('data-report');
    if (!pid || !format) {
      return;
    }

    window.open('/api/report/' + pid + '?format=' + format, format === 'md' ? '_self' : '_blank');
  });

  policyProfilesPanel.addEventListener('click', function (event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    const profileName = target.getAttribute('data-policy-profile');
    if (!profileName) {
      return;
    }

    applyPolicyProfile(profileName);
  });

  render();
  refreshPolicyProfiles();

  const socket = window.io();

  socket.on('connect', function () {
    setConnectionStatus('connected', 'Live');
  });

  socket.on('disconnect', function () {
    setConnectionStatus('disconnected', 'Disconnected');
  });

  socket.on('connect_error', function () {
    setConnectionStatus('error', 'Connection Error');
  });

  socket.on('processData', function (payload) {
    const nextState = normalizePayload(payload);
    state.processes = nextState.processes;
    state.thresholds = nextState.thresholds;
    state.summary = nextState.summary;
    state.generatedAt = nextState.generatedAt;
    state.scanNumber = nextState.scanNumber;
    state.scanIntervalSeconds = nextState.scanIntervalSeconds;
    state.lastUpdated = nextState.lastUpdated;

    if (state.selectedPid == null && state.processes.length) {
      state.selectedPid = state.processes[0].pid;
    } else if (state.selectedPid != null && !getSelectedProcess()) {
      state.selectedPid = state.processes.length ? state.processes[0].pid : null;
    }

    render();
    refreshTimeline();
  });

  socket.on('actionQueued', function (payload) {
    if (!payload || !payload.pid || !payload.action) {
      return;
    }
    state.queuedActions[payload.pid] = String(payload.action);
    renderTable();
  });

  socket.on('sandboxEvents', function (events) {
    state.sandboxEvents = Array.isArray(events) ? events : [];
    renderSandboxEvents();
  });

  socket.on('sandboxArtifacts', function (artifacts) {
    state.sandboxArtifacts = Array.isArray(artifacts) ? artifacts : [];
    renderSandboxEvents();
  });
})();
