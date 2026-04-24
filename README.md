# ProcessGuard

ProcessGuard is a Linux process sandbox and behavior monitoring project written in C, with a small Node.js Socket.IO bridge and a React dashboard for visualizing exported process data.

It has two main operating modes:

- `Monitor mode` scans live processes from `/proc`, checks them against simple security rules, logs alerts, and exports the current process state to `live_state.json`.
- `Sandbox mode` runs a command under a strict memory limit using `setrlimit`, which is useful for demonstrating basic resource confinement.

## Features

- Reads process information directly from `/proc`
- Detects suspicious processes based on:
  - memory usage
  - open file descriptor count
  - fork bomb patterns (excessive child process creation via PPID tracking)
- Logs security alerts to `processguard.log`
- Pauses suspicious user processes with `SIGSTOP`
- Protects low-PID system processes from automated action
- Exports process data to `live_state.json` with PPID information
- Streams process data to a frontend using Socket.IO
- Includes simulator programs for memory abuse, file descriptor spam, and fork bombs

## Architecture

The current data flow is:

```text
processguard (C monitor)
  -> live_state.json
  -> web-dashboard/server.js
  -> Socket.IO on port 3001
  -> React frontend
```

How the pieces fit together:

- `processguard` scans `/proc`, evaluates rule violations, logs alerts, and writes `live_state.json`.
- `web-dashboard/server.js` watches `live_state.json` and emits updates to connected frontend clients.
- `frontend/` connects to `http://localhost:3001` and renders the process table and summary stats.

## Repository Structure

```text
ProcessGuard/
|-- conf/               Rule configuration
|-- include/            Header files for the C project
|-- src/                Core ProcessGuard source files
|-- simulators/         Test programs for suspicious behavior
|-- web-dashboard/      Node.js + Socket.IO bridge server
|-- frontend/           React + Vite dashboard UI
|-- live_state.json     Generated process snapshot file
|-- processguard.log    Generated security alert log
`-- README.md           Project documentation
```

Important directories:

- `src/`
  - `main.c`: entry point that switches between monitor mode and sandbox mode
  - `monitor.c`: scans `/proc`, counts memory and file descriptors, writes JSON output
  - `detection.c`: loads thresholds from `conf/rules.conf` and detects violations
  - `control.c`: pauses suspicious processes with `SIGSTOP`
  - `logger.c`: appends alerts to `processguard.log`
  - `sandbox.c`: runs a command with a 20 MB address-space limit
- `include/`
  - shared headers and `ProcessInfo` struct definitions
- `conf/`
  - `rules.conf`: threshold values for memory and file descriptor alerts
- `simulators/`
  - `sim_mem.c`: simulates high memory usage
  - `sim_fd.c`: simulates file descriptor spam
  - `sim_fork.c`: simulates fork bomb pattern
- `web-dashboard/`
  - `server.js`: watches `live_state.json` and broadcasts data on port `3001`
- `frontend/`
  - React dashboard that connects to the Socket.IO server at `http://localhost:3001`

## Prerequisites

ProcessGuard is designed for Linux, because it depends on the `/proc` filesystem and Linux process metadata.

You should have:

- Linux or a Linux environment with `/proc`
- `gcc`
- Node.js and `npm`
- permission to inspect running processes

Recommended package examples:

```bash
sudo apt update
sudo apt install build-essential nodejs npm
```

Important environment notes:

- The C monitor will not work correctly on native Windows because it reads `/proc/...`.
- You may need `sudo` to inspect `/proc/<pid>/fd` for other users' processes.
- Enforcement can fail without sufficient permissions, even if detection succeeds.
- The frontend depends on the Socket.IO server being available on `http://localhost:3001`.

## Build Instructions

Run all commands from the project root unless noted otherwise.

### Build the main ProcessGuard binary

```bash
gcc -Iinclude src/*.c -o processguard
```

### Build the simulator binaries

```bash
gcc simulators/sim_mem.c -o sim_mem
gcc simulators/sim_fd.c -o sim_fd
gcc simulators/sim_fork.c -o sim_fork
```

## Usage

### 1. Monitor Mode

Run ProcessGuard without extra arguments to scan current processes:

```bash
./processguard
```

What monitor mode currently does:

- loads rules from `conf/rules.conf`
- performs a one-time scan of `/proc`
- prints process information to the terminal
- exports results to `live_state.json`
- logs alerts to `processguard.log`
- pauses suspicious processes when rule violations are found

Important limitation:

- This is currently a one-shot scan, not a continuously running daemon. If you want fresh data, run `./processguard` again.

### 2. Sandbox Mode

Run ProcessGuard with a command to execute that command inside the sandbox:

```bash
./processguard <command> [args...]
```

Example:

```bash
./processguard ls -l
```

Current sandbox behavior:

- forks a child process
- applies `RLIMIT_AS`
- limits the child to `20 MB` of address space
- runs the requested command with `execvp`
- waits for the command to finish

Important limitation:

- The sandbox is currently a basic memory-limited launcher. It is not a full container or hardened security sandbox.

## Dashboard Setup

The dashboard has two parts that must run together:

1. the Socket.IO bridge in `web-dashboard/`
2. the React frontend in `frontend/`

### Start the Socket.IO bridge

Open a terminal and run:

```bash
cd web-dashboard
npm install
node server.js
```

Expected behavior:

- starts an Express/HTTP server with Socket.IO
- listens on port `3001`
- watches `../live_state.json`
- emits `processData` events to connected frontend clients

### Start the React frontend

Open another terminal and run:

```bash
cd frontend
npm install
npm run dev
```

Expected behavior:

- starts the Vite development server
- connects to `http://localhost:3001`
- displays process stats and a process table

### Typical end-to-end workflow

Use three terminals:

Terminal 1:

```bash
cd web-dashboard
node server.js
```

Terminal 2:

```bash
cd frontend
npm run dev
```

Terminal 3:

```bash
./processguard
```

Then refresh or open the frontend in your browser. Each time you run `./processguard`, the exported `live_state.json` is updated and the dashboard can receive new data.

## Rule Configuration

Rules are loaded from:

```text
conf/rules.conf
```

Current example:

```ini
MAX_MEMORY_KB=500000
MAX_FD_COUNT=50
MAX_CHILDREN_PER_PPID=30
```

What these values mean:

- `MAX_MEMORY_KB`: trigger an alert if a process exceeds this resident memory value
- `MAX_FD_COUNT`: trigger an alert if a process has more open file descriptors than this limit
- `MAX_CHILDREN_PER_PPID`: trigger a fork bomb alert if a single parent PID spawns more than this number of active children

How the engine behaves:

- if either threshold is exceeded, ProcessGuard logs a threat
- the process may then be paused with `SIGSTOP`
- if a fork bomb pattern is detected (single PPID with excessive children), ProcessGuard sends `SIGSTOP` to the parent and all its children
- if the PID is `<= 100`, ProcessGuard refuses to act as a safeguard

Fallback behavior:

- if `conf/rules.conf` cannot be opened, built-in defaults are used
- the source currently defaults to `500000` kB for memory, `100` for file descriptors, and `30` for max children per PPID

## Simulator Usage

The project includes three simple simulator programs for demos and testing.

### Memory abuse simulator

```bash
./sim_mem
```

Behavior:

- attempts to allocate about `600 MB` of memory
- sleeps briefly so ProcessGuard has time to detect it

### File descriptor spam simulator

```bash
./sim_fd
```

Behavior:

- opens `60` files rapidly using `/dev/null`
- sleeps briefly so ProcessGuard has time to detect it

### Fork bomb simulator

```bash
./sim_fork
```

Behavior:

- spawns `35` child processes via `fork()`
- each child sleeps briefly to maintain detection window
- parent waits for all children
- triggers fork bomb detection when children count exceeds `MAX_CHILDREN_PER_PPID`

**Dead Man's Switch**: All simulators include `alarm()` calls to self-terminate after a fixed duration (10-15 seconds) as a safety mechanism in case ProcessGuard fails to detect or mitigate them.

### Suggested demo flow

1. Build `processguard`, `sim_mem`, `sim_fd`, and `sim_fork`
2. Start the dashboard server and frontend
3. Run one simulator in a separate terminal
4. Run `./processguard`
5. Check:
   - terminal output
   - `processguard.log`
   - `live_state.json`
   - frontend dashboard updates

## Generated Files

### `live_state.json`

Generated by monitor mode in the project root.

Contains:

- process ID
- parent process ID (PPID)
- process name
- memory usage in kB
- open file descriptor count
- alert status and reasons

Used by:

- `web-dashboard/server.js`
- the React frontend, through Socket.IO updates

### `processguard.log`

Generated by the logger in the project root.

Contains:

- timestamped security alerts
- action logs for paused processes

## Safety Notes

Be careful when running this project on a real Linux system.

- ProcessGuard can send `SIGSTOP` to detected processes.
- You should test with the simulator programs first.
- Run with elevated privileges only when needed.
- Never assume the current sandbox mode is equivalent to a production-grade isolation system.
- The low-PID safeguard helps, but it is not a complete protection strategy.

## Limitations

The current implementation has a few important constraints:

- Linux-only monitor behavior due to `/proc` dependency
- one-shot monitor execution instead of continuous monitoring
- simple threshold-based detection only
- JSON export is rewritten on each scan
- frontend data appears only after `live_state.json` exists
- Socket.IO bridge watches a file rather than reading directly from the monitor process
- sandbox mode limits memory only; it does not isolate filesystem, network, or syscalls

## Troubleshooting

### `live_state.json` is missing

Possible causes:

- `./processguard` has not been run yet
- monitor mode failed before writing the file
- you ran the command from an unexpected working directory

What to do:

- run `./processguard` from the project root
- verify `/proc` is available
- check terminal errors

### Frontend is not receiving data

Possible causes:

- `web-dashboard/server.js` is not running
- frontend is not running
- Socket.IO server is not on port `3001`
- `live_state.json` does not exist yet

What to do:

- start `node server.js` in `web-dashboard/`
- start `npm run dev` in `frontend/`
- run `./processguard` again to refresh `live_state.json`
- confirm the frontend is connecting to `http://localhost:3001`

### Permission denied when reading `/proc/<pid>/fd`

Possible causes:

- the process belongs to another user
- the current shell lacks sufficient privileges

What to do:

- rerun the monitor with `sudo` if appropriate
- test using your own simulator processes first

### No threats are detected

Possible causes:

- thresholds in `conf/rules.conf` are too high
- the simulator process ended before scanning
- the process did not exceed the configured limit

What to do:

- reduce values in `conf/rules.conf`
- run a simulator and quickly launch `./processguard`
- inspect `live_state.json` to confirm the measured values

### Sandbox command fails to execute

Possible causes:

- the command does not exist in `PATH`
- the memory limit is too restrictive
- `execvp` failed

What to do:

- try a known command such as `./processguard ls`
- verify the command is installed
- inspect terminal output for the execution failure message

## Quick Command Reference

```bash
# Build
gcc -Iinclude src/*.c -o processguard
gcc simulators/sim_mem.c -o sim_mem
gcc simulators/sim_fd.c -o sim_fd
gcc simulators/sim_fork.c -o sim_fork

# Monitor mode
./processguard

# Sandbox mode
./processguard ls -l

# Socket.IO bridge
cd web-dashboard
npm install
npm run dev

# Frontend
cd frontend
npm install
npm run dev
```

## Summary

ProcessGuard is a compact Linux security project for demonstrating:

- process inspection using `/proc`
- rule-based suspicious process detection
- simple enforcement with `SIGSTOP`
- basic sandboxed command execution
- web-based visualization using Socket.IO and React

For the safest demo experience, use the included simulators first, confirm the dashboard pipeline is running, and treat the monitor as a controlled educational tool rather than a production security system.
