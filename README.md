# Vigil

<p align="center">
  <strong>Real-time Linux security monitoring from your terminal.</strong><br />
  Visibility into processes, network activity, SSH authentication, and file integrity — in one focused dashboard.
</p>

<p align="center">
  <em>“btop shows you what's running. Vigil helps you see what's wrong.”</em>
</p>

---

## Overview

Vigil is a Linux security monitoring tool written in **C++17**. It combines system visibility with practical security detections in a terminal dashboard, helping operators investigate suspicious process activity, unexpected network changes, SSH authentication events, and file modifications.

Vigil is designed to run locally and make its findings inspectable. Most monitoring features work without elevated privileges; access to protected authentication logs may require running with `sudo`.

## Capabilities

| Area | What Vigil provides |
| --- | --- |
| **System overview** | Live CPU usage, per-core activity, memory usage, and date/time |
| **Process monitoring** | Process metadata, sorting, search, detail view, and suspicious-path highlighting |
| **Network monitoring** | Interface traffic, active connections, listening ports, and connection-change detection |
| **SSH monitoring** | Failed and successful authentication events, source IPs, usernames, and brute-force threshold detection |
| **File integrity** | Built-in SHA-256 checks for file creation, modification, and deletion |
| **Detection rules** | Rules for suspicious execution paths, deleted executables, root processes in suspicious locations, and network changes |
| **Event history** | Categorized events, severity levels, keyword search, and persistent JSONL logging |
| **Alerting** | Terminal bell and optional desktop notifications |

### Detection examples

Vigil can highlight or report:

- Processes executing from locations such as `/tmp`, `/dev/shm`, `/run/user`, and `/var/tmp`.
- Processes that continue running after their executable has been deleted.
- Root-owned processes launched from suspicious locations.
- Newly opened listening ports and suspicious outbound connections.
- Repeated SSH authentication failures within a configurable time window.
- Changes to configured files and directories.

> **Scope note:** Vigil is a monitoring and alerting tool. Do not interpret an alert as proof of compromise. Validate findings in the context of your host, workloads, and expected activity.

## Quick start

### Requirements

- Linux
- GCC 10+ or Clang 12+ with C++17 support
- CMake 3.16+
- Internet access during the initial test dependency fetch (GoogleTest is fetched by CMake)

### Build from source

```bash
git clone https://github.com/ClashFlash/Vigil.git
cd Vigil

make release
make test
```

For a debug build with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
make debug
```

### Run

```bash
./build/release/vigil
```

Most features work as an ordinary user. Reading protected authentication logs may require elevated privileges:

```bash
sudo ./build/release/vigil
```

Run with the least privileges necessary for your environment.

### Manual CMake build

```bash
cmake -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug -j"$(nproc)"

cmake -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release -j"$(nproc)"
```

## Using the dashboard

| Key | Action |
| --- | --- |
| `Tab` / `1`–`4` | Switch panel |
| `q` | Quit |
| `h` | Open help |
| `↑` / `↓` | Navigate or scroll |
| `Enter` | Open process details |
| `Esc` | Return from process details |
| `c` / `m` / `p` | Sort processes by CPU, memory, or PID |
| `/` | Search processes or events |
| `f` | Cycle event filters |

The event filter cycles through **All → Auth → Process → Network → File → System**.

## Configuration

### Monitored paths

Edit `config/monitored_files.conf` to define the files and directories watched by the file integrity monitor. Use one path per line; directories are watched recursively.

### Alert thresholds

Edit `config/thresholds.conf` to configure alert behavior and SSH failure detection. Example settings:

```ini
terminal_bell=HIGH
desktop_notify=HIGH
ssh_fail_count=5
ssh_fail_window=60
sound_enabled=true
notify_enabled=true
```

The event log is stored as JSON Lines at:

```text
~/.local/share/vigil/events.log
```

## Architecture

Vigil separates system collectors, detection logic, event handling, and terminal presentation.

```text
main.cpp                  Startup orchestration, signals, and shutdown
├── cpu.{hpp,cpp}         /proc/stat parsing and CPU utilization
├── memory.{hpp,cpp}      /proc/meminfo parsing and memory statistics
├── process.{hpp,cpp}     Process enumeration, cache, sorting, and details
├── network.{hpp,cpp}     Network interfaces, sockets, and connection tracking
├── ssh_monitor.{hpp,cpp} Authentication log and journal monitoring
├── file_integrity.*      SHA-256 baselines and file-change detection
├── security_rules.*      Detection rules and event deduplication
├── event_system.*        Thread-safe event buffer and JSONL persistence
├── alert.*               Terminal and desktop notifications
├── config.*              Configuration parsing and defaults
└── ui.*                  Terminal dashboard and input event loop
```

### Reliability considerations

- Thread-safe snapshots are used by the UI when displaying process and connection data.
- The terminal input loop uses POSIX `select()` with a short polling interval to remain responsive.
- Background workers are signaled during shutdown so they can exit cleanly on `SIGINT` and `SIGTERM`.
- Listening-port alerts are deduplicated to reduce repeated notifications for the same active change.

## Tests

Vigil includes a GoogleTest suite covering core parsing, monitoring, and detection behavior. The current project documentation records **61 unit tests** across CPU monitoring, SSH parsing, file integrity, security rules, network parsing, process monitoring, and configuration handling.

Run the tests with:

```bash
make test
```

Or, after configuring a debug build:

```bash
cd build/debug
ctest --output-on-failure
```

## Contributing

Contributions, bug reports, and improvement ideas are welcome.

1. Open an issue to describe a bug or proposed change.
2. Fork the repository and create a focused feature branch.
3. Keep changes scoped and include tests where practical.
4. Run the test suite before submitting.
5. Open a pull request with a clear summary, motivation, and testing notes.

Please avoid including real credentials, private logs, or sensitive host data in issues and pull requests.

## Security

If you believe you have found a security vulnerability, please avoid publishing exploit details or sensitive information in a public issue. Contact the repository maintainer privately through the contact options available on the GitHub profile.

## Project

**Created and maintained by Flashy | Shivam**

Repository: [github.com/ClashFlash/Vigil](https://github.com/ClashFlash/Vigil)

### License and commercial use

A license file was not present in the repository when this README was reviewed. Until the project publishes an explicit open-source license, users should not assume that they have permission to use, modify, distribute, or commercially exploit the code.

For a genuinely commercial-friendly open-source release, the maintainers should select and add a license (for example, Apache License 2.0 after confirming contributor rights and dependency compatibility). The license file, not this README, defines the applicable permissions and conditions.
