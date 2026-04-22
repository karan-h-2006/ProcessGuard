# ProcessGuard

ProcessGuard is a Linux-first OS course project that safely demonstrates three ideas together:

1. process monitoring through `/proc`
2. rule-based suspicious behavior detection
3. supervised sandbox-first execution before optional host promotion

The project is intentionally built for safe demos first. By default it does not auto-promote sandboxed commands into normal host execution, and its bundled simulators are capped, time-bounded, and designed to clean themselves up.

## Safety First

Use this project only in a Linux environment such as:

- Ubuntu in VirtualBox/VMware
- WSL2 with a Linux distro
- a disposable lab machine

Important safety choices already built into the code:

- suspicious processes are only acted on after repeated alerts across multiple scans
- default response mode is `pause`, not `kill`
- ProcessGuard skips low-PID and protected processes
- cross-user actions are blocked by default
- sandbox review has memory, CPU, FD, file-size, and timeout limits
- sandbox review has a forced shutdown path with `SIGTERM` followed by `SIGKILL`
- sandbox promotion is disabled by default to avoid running the same command twice
- simulators have hard upper bounds and automatic alarms

Recommended demo practice:

- run inside a VM or WSL2
- test only with the included simulators first
- do not enable `SANDBOX_PROMOTE_AFTER_CLEAN=1` unless the command is safe to run twice
- do not run the monitor as `root` unless you specifically need wider visibility

## What Changed

Compared with the original version, this refactor adds:

- continuous monitoring driven by configurable scan intervals
- richer telemetry: CPU, threads, sockets, child-count, command line, uptime, memory growth
- scored detections instead of only fixed memory and FD checks
- persistence-aware actions so one noisy sample does not trigger enforcement immediately
- safer and more explicit response policy: `pause`, `terminate`, or `kill`
- ownership-aware safeguards to avoid touching protected or foreign-user processes by default
- a supervised sandbox review stage with hard limits and force-stop logic
- safer malware simulators with bounded resource use
- richer dashboard data and clearer action visibility

## Project Structure

```text
ProcessGuard/
|-- conf/               Rule configuration
|-- include/            Shared C headers
|-- src/                Core monitor, detection, control, sandbox, logger
|-- simulators/         Safe demo simulators
|-- web-dashboard/      Socket.IO bridge for live_state.json
|-- processguard-ui/    React dashboard
`-- README.md
```

Core modules:

- `src/main.c`
  switches between monitor mode and sandbox review mode
- `src/monitor.c`
  scans `/proc`, enriches process telemetry, and writes `live_state.json`
- `src/detection.c`
  loads rules, scores suspicious behavior, and coordinates enforcement
- `src/control.c`
  applies guarded pause/terminate/kill actions
- `src/sandbox.c`
  runs commands under a supervised sandbox review stage
- `src/logger.c`
  appends security events to `processguard.log`

## Detection Model

The detection engine now scores processes using multiple signals:

- resident memory usage
- file descriptor count
- socket count
- thread count
- CPU percentage
- rapid memory growth between scans
- rapid file descriptor growth between scans
- excessive child-process fan-out from one parent

Actions are only considered when:

- the score crosses `MIN_ALERT_SCORE`
- the alert persists for `ALERT_PERSISTENCE_CYCLES`

This helps reduce false positives from short-lived spikes.

## Rule Configuration

Rules live in [conf/rules.conf](/C:/Btech/sem4/IT253/project/ProcessGuard/conf/rules.conf).

Key settings:

```ini
MONITOR_INTERVAL_SECONDS=2
MAX_MEMORY_KB=500000
MAX_FD_COUNT=128
MAX_SOCKET_COUNT=32
MAX_THREADS=64
MAX_CPU_PERCENT=85
MAX_MEMORY_GROWTH_KB=128000
MAX_FD_GROWTH=32
MAX_CHILDREN_PER_PPID=24
MIN_ALERT_SCORE=40
ALERT_PERSISTENCE_CYCLES=2
ACTION_MODE=pause
SANDBOX_MEMORY_KB=131072
SANDBOX_FD_LIMIT=64
SANDBOX_CPU_SECONDS=15
SANDBOX_EVAL_SECONDS=8
SANDBOX_PROMOTE_AFTER_CLEAN=0
```

Action policy:

- `pause`: safest default, uses `SIGSTOP`
- `terminate`: sends `SIGTERM` and escalates to `SIGKILL` after the grace period
- `kill`: immediate `SIGKILL`

## Build

Run these commands inside Linux:

```bash
gcc -Iinclude src/*.c -o processguard
gcc simulators/sim_mem.c -o sim_mem
gcc simulators/sim_fd.c -o sim_fd
gcc simulators/sim_fork.c -o sim_fork
gcc simulators/sim_cpu.c -o sim_cpu
gcc simulators/sim_socket.c -o sim_socket
gcc simulators/sim_combo.c -o sim_combo
```

Or build everything at once:

```bash
make
```

The C core is Linux-specific because it depends on `/proc`, `setrlimit`, Unix signals, and Linux process metadata.

## Running ProcessGuard

### Monitor Mode

```bash
./processguard
```

What it does:

- loads `conf/rules.conf`
- scans live processes every configured interval
- writes `live_state.json`
- logs events to `processguard.log`
- scores suspicious behavior
- applies guarded actions only after sustained alerts

Stop it safely with `Ctrl+C`.

### Sandbox Review Mode

```bash
./processguard <command> [args...]
```

Example:

```bash
./processguard ./sim_mem 96 8
```

What sandbox review does:

- runs the target in a restricted environment first
- applies memory, CPU, FD, file-size, and timeout limits
- supervises the target during the review window
- force-stops the sandboxed process group if limits are exceeded
- does not promote to host execution unless `SANDBOX_PROMOTE_AFTER_CLEAN=1`

Important note:

- if you enable promotion, the command is executed again outside the sandbox after a clean review
- only use promotion for commands that are safe to run twice

## Safe Simulator Programs

All simulator source lives in [simulators](/C:/Btech/sem4/IT253/project/ProcessGuard/simulators).

### Memory simulator

Build:

```bash
gcc simulators/sim_mem.c -o sim_mem
```

Run:

```bash
./sim_mem
./sim_mem 128 10
```

Arguments:

- first argument: megabytes to allocate
- second argument: seconds to hold the allocation

Safety caps:

- minimum 8 MB
- maximum 192 MB
- maximum hold time 12 seconds

### File descriptor simulator

Build:

```bash
gcc simulators/sim_fd.c -o sim_fd
```

Run:

```bash
./sim_fd
./sim_fd 72 8
```

Arguments:

- first argument: number of descriptors to open
- second argument: seconds to keep them open

Safety caps:

- minimum 8 FDs
- maximum 96 FDs
- maximum hold time 12 seconds

### Process family simulator

Build:

```bash
gcc simulators/sim_fork.c -o sim_fork
```

Run:

```bash
./sim_fork
./sim_fork 16 8
```

Arguments:

- first argument: number of child processes
- second argument: seconds to keep them alive

Safety caps:

- minimum 2 children
- maximum 20 children
- maximum hold time 12 seconds

### CPU simulator

Build:

```bash
gcc simulators/sim_cpu.c -o sim_cpu
```

Run:

```bash
./sim_cpu
./sim_cpu 10
```

### Socket simulator

Build:

```bash
gcc simulators/sim_socket.c -o sim_socket
```

Run:

```bash
./sim_socket
./sim_socket 20 8
```

### Combo simulator

Build:

```bash
gcc simulators/sim_combo.c -o sim_combo
```

Run:

```bash
./sim_combo
./sim_combo 112 40 8
```

## Suggested Demo Flow

1. Start in a Linux VM or WSL2 terminal.
2. Build `processguard` and the simulators.
3. Start the dashboard bridge and frontend.
4. Launch one simulator.
5. Start `./processguard`.
6. Watch terminal logs, `processguard.log`, `live_state.json`, and the dashboard.

Every bundled simulator now matches the detection engine in two ways:

- it crosses one or more behavior thresholds
- it carries a known demo signature so it is guaranteed to appear as an alert in the dashboard

The dashboard also exposes real-time user actions for alerted processes:

- `Continue` resumes the process and suppresses further automatic stopping for that PID
- `Pause` sends it back to `SIGSTOP`
- `Stop` sends `SIGTERM` and escalates if needed
- `Kill` sends `SIGKILL`

Example:

Terminal 1:

```bash
cd web-dashboard
npm install
npm run dev
```

Then open:

```text
http://localhost:3001
```

Important:

- the dashboard is now served directly by `web-dashboard`
- if port `3001` is already busy, the server falls back to `http://localhost:3002`

Terminal 2:

```bash
./sim_mem 128 10
./processguard
```

To build all available simulator binaries before testing:

```bash
make simulators
```

## Dashboard

The dashboard now shows:

- process score
- CPU usage
- memory and memory growth
- FD count
- socket count
- thread count
- child-process count
- whether ProcessGuard acted
- whether a process was protected and intentionally skipped

Bridge server:

```bash
cd web-dashboard
node server.js
```

Open the dashboard in your browser at `http://localhost:3001`.

## Generated Files

- `live_state.json`
  latest structured process snapshot for the dashboard
- `processguard.log`
  timestamped alert and action log
- `sandbox_workspace/`
  working directory used by sandbox review for relative-path writes

## Limitations

This is still an educational security project, not a production EDR or container runtime.

Known limits:

- Linux-only C core
- sandbox review uses `setrlimit` and supervision, not full namespace/container isolation
- there is no syscall-level policy engine
- promotion can duplicate side effects if enabled for non-idempotent commands
- some `/proc/<pid>/fd` reads can still be permission-limited

## Good Submission Talking Points

If you need to explain the project in class, highlight:

- sandbox-first review before optional host execution
- dynamic behavior scoring instead of one fixed threshold
- safe default actions and protected-process safeguards
- live monitoring pipeline from C core to web dashboard
- safe malware simulation for demonstration and testing
