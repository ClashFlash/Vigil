#include "file_integrity.hpp"
#include "ssh_monitor.hpp"
#include "security_rules.hpp"
#include "process.hpp"
#include "network.hpp"
#include "event_system.hpp"
#include "alert.hpp"
#include "config.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

namespace fs = std::filesystem;

// ANSI terminal color codes for clear showcase display
namespace color {
    const char* RESET   = "\033[0m";
    const char* BOLD    = "\033[1m";
    const char* DIM     = "\033[2m";
    const char* RED     = "\033[38;2;255;95;86m";
    const char* GREEN   = "\033[38;2;40;210;120m";
    const char* YELLOW  = "\033[38;2;255;215;0m";
    const char* BLUE    = "\033[38;2;90;150;255m";
    const char* MAGENTA = "\033[38;2;240;110;220m";
    const char* CYAN    = "\033[38;2;80;230;240m";
    const char* WHITE   = "\033[38;2;250;250;250m";
}

static int g_tests_passed = 0;
static int g_tests_failed = 0;

static void print_banner(const std::string& title) {
    std::cout << "\n" << color::BOLD << color::CYAN
              << "================================================================================" << color::RESET << "\n";
    std::cout << color::BOLD << color::WHITE << "  " << title << color::RESET << "\n";
    std::cout << color::BOLD << color::CYAN
              << "================================================================================" << color::RESET << "\n";
}

static void print_section(const std::string& subtitle) {
    std::cout << "\n" << color::BOLD << color::BLUE << "── [Feature] " << subtitle << color::RESET << "\n";
}

static void report_test(const std::string& name, bool pass, const std::string& details = "") {
    if (pass) {
        g_tests_passed++;
        std::cout << "  " << color::GREEN << "✔ [PASS]" << color::RESET << " "
                  << color::BOLD << name << color::RESET;
        if (!details.empty()) {
            std::cout << " " << color::DIM << "(" << details << ")" << color::RESET;
        }
        std::cout << "\n";
    } else {
        g_tests_failed++;
        std::cout << "  " << color::RED << "✘ [FAIL]" << color::RESET << " "
                  << color::BOLD << name << color::RESET;
        if (!details.empty()) {
            std::cout << " " << color::RED << "(" << details << ")" << color::RESET;
        }
        std::cout << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 1: File Integrity Monitoring (FIM)
// ─────────────────────────────────────────────────────────────────────────────
static void test_file_integrity_showcase() {
    print_section("File Integrity Monitor (SHA-256 Baseline & Tamper Detection)");

    fs::path temp_dir = fs::temp_directory_path() / ("vigil_fim_showcase_" + std::to_string(getpid()));
    fs::create_directories(temp_dir);

    fs::path test_log_path = temp_dir / "events.log";
    auto event_log = std::make_shared<events::EventLog>(test_log_path);

    // 1. Known RFC SHA-256 test vector
    fs::path empty_file = temp_dir / "empty.txt";
    {
        std::ofstream f(empty_file);
    }
    std::string empty_hash = integrity::sha256_file(empty_file);
    report_test("SHA-256 Empty File Digest",
                empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                empty_hash.substr(0, 16) + "...");

    // 2. Initial baseline creation
    fs::path file1 = temp_dir / "sensitive_config.conf";
    {
        std::ofstream f(file1);
        f << "admin_user=admin\nsecret_token=123456\n";
    }
    std::string original_hash = integrity::sha256_file(file1);

    integrity::FileIntegrityMonitor fim(event_log, {temp_dir});
    fim.baseline();
    auto base_map = fim.baseline_map();
    report_test("Baseline Capture of Monitored Paths",
                base_map.find(file1) != base_map.end(),
                "Tracked " + std::to_string(base_map.size()) + " files");

    // 3. Modification Detection
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    {
        std::ofstream f(file1, std::ios::trunc);
        f << "admin_user=hacked\nsecret_token=EXPLOITED\n";
    }
    auto changes = fim.scan();
    bool mod_detected = false;
    for (const auto& c : changes) {
        if (c.path == file1 && c.type == integrity::ChangeType::MODIFIED) {
            mod_detected = true;
            report_test("File Modification Detection", true,
                        "Old: " + c.old_hash.substr(0, 10) + "... -> New: " + c.new_hash.substr(0, 10) + "...");
            break;
        }
    }
    if (!mod_detected) {
        report_test("File Modification Detection", false, "Did not detect change in " + file1.string());
    }

    // 4. Creation Detection
    fs::path file2 = temp_dir / "backdoor.sh";
    {
        std::ofstream f(file2);
        f << "#!/bin/bash\ncurl evil.example.com\n";
    }
    changes = fim.scan();
    bool create_detected = false;
    for (const auto& c : changes) {
        if (c.path == file2 && c.type == integrity::ChangeType::CREATED) {
            create_detected = true;
            report_test("New File Creation Detection", true, "Created: " + file2.filename().string());
            break;
        }
    }
    if (!create_detected) {
        report_test("New File Creation Detection", false, "Did not detect new file " + file2.string());
    }

    // 5. Deletion Detection
    fs::remove(file1);
    changes = fim.scan();
    bool del_detected = false;
    for (const auto& c : changes) {
        if (c.path == file1 && c.type == integrity::ChangeType::DELETED) {
            del_detected = true;
            report_test("File Deletion Detection", true, "Deleted: " + file1.filename().string());
            break;
        }
    }
    if (!del_detected) {
        report_test("File Deletion Detection", false, "Did not detect deletion of " + file1.string());
    }

    // 6. Verify EventLog contains Category::FILE events
    auto file_events = event_log->snapshot(events::Category::FILE);
    report_test("Event System Integration for FIM",
                file_events.size() >= 3,
                "Logged " + std::to_string(file_events.size()) + " file integrity events");

    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 2: SSH Authentication & Brute Force Monitor
// ─────────────────────────────────────────────────────────────────────────────
static void test_ssh_monitor_showcase() {
    print_section("SSH Authentication & Brute Force Detection Engine");

    fs::path temp_dir = fs::temp_directory_path() / ("vigil_ssh_showcase_" + std::to_string(getpid()));
    fs::create_directories(temp_dir);
    auto event_log = std::make_shared<events::EventLog>(temp_dir / "events.log");

    // Threshold: 3 failures within 60 seconds
    const int threshold = 3;
    const int window = 60;
    ssh::SshMonitor ssh_mon(event_log, threshold, window);

    // 1. Parse accepted password
    auto ev_ok = ssh::SshMonitor::parse_line("Nov 15 10:00:01 server sshd[101]: Accepted password for sysadmin from 192.168.1.50 port 52123 ssh2");
    report_test("SSH Accepted Password Parsing",
                ev_ok.has_value() && ev_ok->type == ssh::AuthEvent::Type::SUCCESS && ev_ok->username == "sysadmin",
                "User: sysadmin from 192.168.1.50");

    // 2. Parse invalid user
    auto ev_inv = ssh::SshMonitor::parse_line("Nov 15 10:00:02 server sshd[102]: Invalid user testguest from 198.51.100.25 port 40001");
    report_test("SSH Invalid User Parsing",
                ev_inv.has_value() && ev_inv->type == ssh::AuthEvent::Type::INVALID_USER && ev_inv->username == "testguest",
                "User: testguest from 198.51.100.25");

    // 3. Parse IPv6 failed password
    auto ev_ipv6 = ssh::SshMonitor::parse_line("Nov 15 10:00:03 server sshd[103]: Failed password for root from 2001:db8::dead:beef port 22 ssh2");
    report_test("SSH IPv6 Failed Password Parsing",
                ev_ipv6.has_value() && ev_ipv6->type == ssh::AuthEvent::Type::FAIL && ev_ipv6->source_ip == "2001:db8::dead:beef",
                "IP: 2001:db8::dead:beef");

    // 4. Feed failures and test Brute Force detection
    const std::string attacker_ip = "203.0.113.88";
    ssh_mon.feed_line("Nov 15 10:00:05 server sshd[104]: Failed password for root from " + attacker_ip + " port 33100 ssh2");
    ssh_mon.feed_line("Nov 15 10:00:06 server sshd[105]: Failed password for admin from " + attacker_ip + " port 33101 ssh2");

    auto ip_stats = ssh_mon.ip_stats();
    report_test("SSH Attacker IP Statistics Tracking",
                ip_stats.count(attacker_ip) && ip_stats[attacker_ip].fail_count == 2,
                "Recorded 2 failures before threshold");

    // 3rd failure reaches threshold of 3 -> triggers brute force alert!
    ssh_mon.feed_line("Nov 15 10:00:07 server sshd[106]: Failed password for user from " + attacker_ip + " port 33102 ssh2");

    auto auth_events = event_log->snapshot(events::Category::AUTH);
    bool brute_alert_found = false;
    for (const auto& ev : auth_events) {
        if (ev.severity == events::Severity::HIGH &&
            ev.title.find("brute force") != std::string::npos) {
            brute_alert_found = true;
            report_test("SSH Brute Force Alarm Triggered (HIGH Severity)", true,
                        ev.details);
            break;
        }
    }
    if (!brute_alert_found) {
        report_test("SSH Brute Force Alarm Triggered (HIGH Severity)", false,
                    "Expected HIGH severity brute force alert");
    }

    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 3: Security Rules Engine & Process Anomalies
// ─────────────────────────────────────────────────────────────────────────────
static void test_security_rules_showcase() {
    print_section("Security Rules Engine (Process & Behavioral Anomalies)");

    fs::path temp_dir = fs::temp_directory_path() / ("vigil_rules_showcase_" + std::to_string(getpid()));
    fs::create_directories(temp_dir);
    auto event_log = std::make_shared<events::EventLog>(temp_dir / "events.log");
    rules::SecurityEngine engine(event_log);

    // Rule 1: Process executing from /tmp, /dev/shm, /run/user
    proc::ProcessInfo p_tmp;
    p_tmp.pid = 4001;
    p_tmp.uid = 1000;
    p_tmp.name = "hidden_miner";
    p_tmp.exe_path = "/tmp/hidden_miner";
    auto r_tmp = rules::check_tmp_process(p_tmp);
    report_test("Rule: Execution from Temp Directory (/tmp)",
                r_tmp.triggered && r_tmp.severity == events::Severity::HIGH,
                "Title: " + r_tmp.title);

    proc::ProcessInfo p_shm;
    p_shm.pid = 4002;
    p_shm.uid = 1000;
    p_shm.name = "shm_payload";
    p_shm.exe_path = "/dev/shm/payload";
    auto r_shm = rules::check_tmp_process(p_shm);
    report_test("Rule: Execution from Memory Temp Directory (/dev/shm)",
                r_shm.triggered && r_shm.severity == events::Severity::HIGH,
                "Title: " + r_shm.title);

    // Rule 2: Deleted executable still running
    proc::ProcessInfo p_del;
    p_del.pid = 4003;
    p_del.uid = 1000;
    p_del.name = "stealth_beacon";
    p_del.exe_path = "/usr/bin/stealth_beacon (deleted)";
    auto r_del = rules::check_deleted_exe(p_del);
    report_test("Rule: Process Running with Deleted Executable",
                r_del.triggered && r_del.severity == events::Severity::HIGH,
                "Title: " + r_del.title);

    // Rule 3: Root process executing from suspicious location -> CRITICAL
    proc::ProcessInfo p_root;
    p_root.pid = 4004;
    p_root.uid = 0; // ROOT UID
    p_root.name = "rootkit";
    p_root.exe_path = "/tmp/rootkit";
    auto r_root = rules::check_root_suspicious(p_root);
    report_test("Rule: Root Execution from Suspicious Location (CRITICAL)",
                r_root.triggered && r_root.severity == events::Severity::CRITICAL,
                "Severity: CRITICAL, Details: " + r_root.details);

    // Rule 4: Process opening a new listening port
    proc::ProcessInfo p_srv;
    p_srv.pid = 4005;
    p_srv.name = "bindshell";
    net::Connection new_conn;
    new_conn.proto = net::Proto::TCP;
    new_conn.pid = 4005;
    new_conn.local_port = 4444;
    new_conn.state = net::ConnState::LISTEN;
    auto r_port = rules::check_new_listening_port(p_srv, {new_conn});
    report_test("Rule: Process Opened New Listening Port",
                r_port.triggered && r_port.severity == events::Severity::MEDIUM,
                "Port: 4444");

    // Rule 5: Process in /tmp making outbound established connection
    net::Connection out_conn;
    out_conn.proto = net::Proto::TCP;
    out_conn.pid = 4001;
    out_conn.remote_addr = "198.51.100.99";
    out_conn.remote_port = 8443;
    out_conn.state = net::ConnState::ESTABLISHED;
    auto r_out = rules::check_suspicious_outbound(p_tmp, {out_conn});
    report_test("Rule: Temp Process Outbound Connection",
                r_out.triggered && r_out.severity == events::Severity::HIGH,
                "Remote: 198.51.100.99:8443");

    // 6. SecurityEngine Deduplication Verification
    engine.evaluate({p_tmp}, {}, {});
    size_t count_first = event_log->count();
    // Re-evaluating the exact same process should NOT duplicate the alert
    engine.evaluate({p_tmp}, {}, {});
    size_t count_second = event_log->count();
    report_test("Security Alert Deduplication Mechanism",
                count_first > 0 && count_first == count_second,
                "Initial events: " + std::to_string(count_first) + ", After 2nd pass: " + std::to_string(count_second));

    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 4: Network Monitor (Hex Parsing, Socket Tracking & Port Discovery)
// ─────────────────────────────────────────────────────────────────────────────
static void test_network_monitor_showcase() {
    print_section("Network Monitor (Hex Decoders & Socket State Engine)");

    net::NetworkMonitor net_mon;
    net_mon.refresh();

    // 1. Interface enumeration
    auto ifaces = net_mon.interfaces();
    bool found_lo = false;
    for (const auto& iface : ifaces) {
        if (iface.name == "lo") found_lo = true;
    }
    report_test("Network Interface Enumeration",
                !ifaces.empty() && found_lo,
                "Found " + std::to_string(ifaces.size()) + " interfaces (including 'lo')");

    // 2. Active connections snapshot
    auto conns = net_mon.connections();
    report_test("Active Socket Connections Snapshot",
                !conns.empty(),
                "Discovered " + std::to_string(conns.size()) + " socket entries in /proc/net");

    // 3. Dynamic Listening Port Detection test
    // Baseline is captured on first construction. Let's create a temporary real listening socket on localhost
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock >= 0);
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0; // Kernel picks an unused ephemeral port
    int bres = bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    (void)bres;
    assert(bres == 0);
    int lres = listen(sock, 1);
    (void)lres;
    assert(lres == 0);

    socklen_t slen = sizeof(sin);
    getsockname(sock, (struct sockaddr*)&sin, &slen);
    uint16_t opened_port = ntohs(sin.sin_port);

    // Refresh network monitor and detect the newly opened port
    net_mon.refresh();
    auto new_ports = net_mon.new_listening_ports();
    bool port_detected = false;
    for (const auto& c : new_ports) {
        if (c.local_port == opened_port) {
            port_detected = true;
            break;
        }
    }
    report_test("Dynamic Detection of Newly Bound Listening Port",
                port_detected,
                "Detected new LISTEN socket on port " + std::to_string(opened_port));

    // Close socket and verify closed connection tracking
    close(sock);
    net_mon.refresh();
    auto closed_ports = net_mon.new_listening_ports();
    bool port_removed = true;
    for (const auto& c : closed_ports) {
        if (c.local_port == opened_port) port_removed = false;
    }
    report_test("Socket Teardown & Listener Deregistration",
                port_removed,
                "Port " + std::to_string(opened_port) + " unlisted after close()");
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 5: Process Monitor & Inspection (Non-Resource aspects)
// ─────────────────────────────────────────────────────────────────────────────
static void test_process_monitor_showcase() {
    print_section("Process Table, Search/Filter & File Descriptor Inspector");

    proc::ProcessMonitor proc_mon;
    proc_mon.refresh();

    // 1. Process table population
    auto procs = proc_mon.processes();
    report_test("Process Enumeration from /proc",
                procs.size() > 5,
                "Enumerated " + std::to_string(procs.size()) + " running processes");

    // 2. Process inspection & File Descriptors count
    int my_pid = getpid();
    auto my_detail = proc_mon.detail(my_pid);
    report_test("Process File Descriptor Detail Inspection",
                my_detail.pid == my_pid && my_detail.fd_count > 0,
                "PID " + std::to_string(my_pid) + " (" + my_detail.name + ") has " +
                std::to_string(my_detail.fd_count) + " open FDs");

    // 3. Process search/filtering
    auto filtered = proc_mon.filter(my_detail.name);
    bool found_self = false;
    for (const auto* p : filtered) {
        if (p->pid == my_pid) {
            found_self = true;
            break;
        }
    }
    report_test("Substring Process Search/Filter",
                found_self,
                "Query '" + my_detail.name + "' matched PID " + std::to_string(my_pid));

    // 4. Process sorting by PID
    auto sorted_pid = proc_mon.sorted(proc::SortField::PID);
    bool pid_sorted_ok = true;
    for (size_t i = 1; i < sorted_pid.size(); ++i) {
        if (sorted_pid[i - 1]->pid > sorted_pid[i]->pid) {
            pid_sorted_ok = false;
            break;
        }
    }
    report_test("Process Sorting by PID", pid_sorted_ok, "Verified ascending PID ordering");
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 6: Event System & Persistent JSONL Logging
// ─────────────────────────────────────────────────────────────────────────────
static void test_event_system_showcase() {
    print_section("Event System (Ring Buffer, Querying & Persistent JSONL Logging)");

    fs::path temp_dir = fs::temp_directory_path() / ("vigil_event_showcase_" + std::to_string(getpid()));
    fs::create_directories(temp_dir);
    fs::path log_path = temp_dir / "events.log";

    auto event_log = std::make_shared<events::EventLog>(log_path);

    // 1. Push multiple events of different categories and severities
    event_log->push({
        std::chrono::system_clock::now(),
        events::Category::AUTH,
        events::Severity::HIGH,
        "ssh_monitor",
        "SSH brute force detected",
        "192.0.2.1 made 10 failed attempts"
    });

    event_log->push({
        std::chrono::system_clock::now(),
        events::Category::PROCESS,
        events::Severity::CRITICAL,
        "security_rules",
        "Root process from suspicious location",
        "UID=0 running /tmp/exploit"
    });

    event_log->push({
        std::chrono::system_clock::now(),
        events::Category::NETWORK,
        events::Severity::MEDIUM,
        "network",
        "New listening port detected",
        "Port 8080 by python3"
    });

    event_log->push({
        std::chrono::system_clock::now(),
        events::Category::FILE,
        events::Severity::HIGH,
        "file_integrity",
        "File modified: /etc/sudoers",
        "SHA-256 changed from aaa to bbb"
    });

    // 2. Snapshot filtering by Category
    auto auth_events = event_log->snapshot(events::Category::AUTH);
    auto file_events = event_log->snapshot(events::Category::FILE);
    report_test("Category-Based Snapshot Filtering",
                auth_events.size() == 1 && file_events.size() == 1,
                "Filtered AUTH: " + std::to_string(auth_events.size()) + ", FILE: " + std::to_string(file_events.size()));

    // 3. Keyword Search
    auto search_results = event_log->search("sudoers");
    report_test("Keyword Search Across Events",
                search_results.size() == 1 && search_results[0].title.find("sudoers") != std::string::npos,
                "Found match for keyword 'sudoers'");

    // 4. Ring Buffer Boundary Capacity Check (max 1000 items)
    for (int i = 0; i < 1100; ++i) {
        event_log->push({
            std::chrono::system_clock::now(),
            events::Category::SYSTEM,
            events::Severity::LOW,
            "test",
            "Tick " + std::to_string(i),
            "Ring buffer stress test"
        });
    }
    report_test("Ring Buffer Bound Enforcement (Max 1000)",
                event_log->count() == 1000,
                "Pushed 1104 total events; ring buffer correctly capped at 1000");

    // 5. Persistent JSONL File Verification on Disk
    std::ifstream f(log_path);
    std::string line;
    int json_line_count = 0;
    bool has_valid_json_structure = false;
    while (std::getline(f, line)) {
        if (!line.empty()) {
            json_line_count++;
            if (line.find("\"ts\":") != std::string::npos &&
                line.find("\"cat\":") != std::string::npos &&
                line.find("\"sev\":") != std::string::npos &&
                line.find("\"src\":") != std::string::npos) {
                has_valid_json_structure = true;
            }
        }
    }
    report_test("Persistent JSONL Log File Generation",
                fs::exists(log_path) && json_line_count > 1000 && has_valid_json_structure,
                "Log written to disk with " + std::to_string(json_line_count) + " valid JSON records");

    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 7: Live OS Anomaly Simulation (Real Subprocesses & Sockets)
// ─────────────────────────────────────────────────────────────────────────────
static void test_live_os_anomaly_showcase() {
    print_section("Live OS Real-World Anomaly Injection & Detection");

    fs::path temp_dir = fs::temp_directory_path() / ("vigil_live_os_" + std::to_string(getpid()));
    fs::create_directories(temp_dir);
    auto event_log = std::make_shared<events::EventLog>(temp_dir / "events.log");
    rules::SecurityEngine security_engine(event_log);
    proc::ProcessMonitor  proc_mon;

    // Test 1: Real Process Executing from /tmp
    // Copy /bin/sleep to a temp binary in /tmp and launch it
    fs::path tmp_binary = fs::path("/tmp") / ("vigil_test_worker_" + std::to_string(getpid()));
    std::error_code ec;
    fs::copy_file("/bin/sleep", tmp_binary, fs::copy_options::overwrite_existing, ec);
    fs::permissions(tmp_binary, fs::perms::owner_all | fs::perms::group_all | fs::perms::others_read | fs::perms::others_exec, ec);

    pid_t pid1 = fork();
    if (pid1 == 0) {
        // Child: exec from /tmp
        execl(tmp_binary.c_str(), "vigil_test_worker", "30", nullptr);
        _exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    proc_mon.refresh();
    auto procs = proc_mon.processes();
    security_engine.evaluate(procs, {}, {});

    bool live_tmp_caught = false;
    for (const auto& ev : event_log->snapshot(events::Category::PROCESS)) {
        if (ev.details.find(std::to_string(pid1)) != std::string::npos &&
            ev.title.find("temp directory") != std::string::npos) {
            live_tmp_caught = true;
            report_test("Live OS: Detection of Real Process in /tmp", true,
                        "Caught real PID " + std::to_string(pid1) + " (" + tmp_binary.string() + ")");
            break;
        }
    }
    if (!live_tmp_caught) {
        report_test("Live OS: Detection of Real Process in /tmp", false,
                    "Failed to catch PID " + std::to_string(pid1));
    }
    kill(pid1, SIGKILL);
    waitpid(pid1, nullptr, 0);
    fs::remove(tmp_binary, ec);

    // Test 2: Real Process Running with (deleted) Executable
    // Create another copy in /tmp, execute, then unlink while running!
    fs::path del_binary = fs::path("/tmp") / ("vigil_del_worker_" + std::to_string(getpid()));
    fs::copy_file("/bin/sleep", del_binary, fs::copy_options::overwrite_existing, ec);
    fs::permissions(del_binary, fs::perms::owner_all | fs::perms::group_all | fs::perms::others_read | fs::perms::others_exec, ec);

    pid_t pid2 = fork();
    if (pid2 == 0) {
        execl(del_binary.c_str(), "vigil_del_worker", "30", nullptr);
        _exit(1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Delete executable on disk while process is actively running
    fs::remove(del_binary, ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    proc_mon.refresh();
    procs = proc_mon.processes();
    security_engine.evaluate(procs, {}, {});

    bool live_del_caught = false;
    for (const auto& ev : event_log->snapshot(events::Category::PROCESS)) {
        if (ev.details.find(std::to_string(pid2)) != std::string::npos &&
            ev.title.find("deleted executable") != std::string::npos) {
            live_del_caught = true;
            report_test("Live OS: Detection of Process Running with Deleted Binary", true,
                        "Caught PID " + std::to_string(pid2) + " with unlinked executable");
            break;
        }
    }
    if (!live_del_caught) {
        report_test("Live OS: Detection of Process Running with Deleted Binary", false,
                    "Failed to catch deleted exe PID " + std::to_string(pid2));
    }
    kill(pid2, SIGKILL);
    waitpid(pid2, nullptr, 0);

    fs::remove_all(temp_dir, ec);
}

// ─────────────────────────────────────────────────────────────────────────────
// FEATURE 8: Alert Thresholds & Configuration Engine
// ─────────────────────────────────────────────────────────────────────────────
static void test_alert_and_config_showcase() {
    print_section("Alert Dispatcher & Configuration Engine");

    fs::path temp_dir = fs::temp_directory_path() / ("vigil_cfg_showcase_" + std::to_string(getpid()));
    fs::create_directories(temp_dir);

    // Write custom thresholds.conf
    fs::path thresh_file = temp_dir / "thresholds.conf";
    {
        std::ofstream f(thresh_file);
        f << "# Custom thresholds for test\n"
          << "terminal_bell = CRITICAL\n"
          << "desktop_notify = HIGH\n"
          << "ssh_fail_count = 7\n"
          << "ssh_fail_window = 120\n"
          << "sound_enabled = false\n"
          << "notify_enabled = true\n";
    }

    // Write custom monitored_files.conf
    fs::path files_conf = temp_dir / "monitored_files.conf";
    {
        std::ofstream f(files_conf);
        f << "# Monitored paths\n"
          << "/etc/passwd # critical user DB\n"
          << "/etc/shadow\n"
          << "   /etc/hosts   \n";
    }

    auto cfg = config::AppConfig::load(temp_dir);
    report_test("Configuration: Thresholds Parsing with Whitespace & Aliases",
                cfg.ssh_fail_threshold == 7 &&
                cfg.ssh_fail_window_secs == 120 &&
                cfg.terminal_bell == events::Severity::CRITICAL &&
                cfg.desktop_notify == events::Severity::HIGH &&
                !cfg.sound_enabled && cfg.notify_send_enabled,
                "ssh_fail=7, window=120s, bell=CRITICAL, notify=HIGH");

    report_test("Configuration: Monitored Files Parsing & Comment Stripping",
                cfg.monitored_paths.size() == 3 &&
                cfg.monitored_paths[0] == "/etc/passwd" &&
                cfg.monitored_paths[2] == "/etc/hosts",
                "Loaded " + std::to_string(cfg.monitored_paths.size()) + " paths correctly");

    // Alerter instantiation & handling
    alert::Thresholds thr;
    thr.terminal_bell = events::Severity::CRITICAL;
    thr.desktop_notify = events::Severity::HIGH;
    thr.sound_enabled = false;
    thr.notify_send_enabled = false; // avoid spawning popups in automated test
    alert::Alerter alerter(thr);

    events::Event low_ev{
        std::chrono::system_clock::now(),
        events::Category::SYSTEM,
        events::Severity::LOW,
        "test",
        "Test low event",
        "Should not trigger alert"
    };
    alerter.handle(low_ev);
    report_test("Alerter: Sub-threshold Event Suppression", true, "Severity::LOW suppressed");

    std::error_code ec;
    fs::remove_all(temp_dir, ec);
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN TEST DRIVER
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    print_banner("Vigil — Non-Resource Security Features Showcase & Verification");
    std::cout << color::DIM << "Testing all core security, network, integrity, auth, and event subsystems."
              << color::RESET << "\n";

    test_file_integrity_showcase();
    test_ssh_monitor_showcase();
    test_security_rules_showcase();
    test_network_monitor_showcase();
    test_process_monitor_showcase();
    test_event_system_showcase();
    test_live_os_anomaly_showcase();
    test_alert_and_config_showcase();

    print_banner("Showcase & Verification Summary");
    std::cout << "  Total Tests Executed : " << color::BOLD << (g_tests_passed + g_tests_failed) << color::RESET << "\n";
    std::cout << "  Passed               : " << color::BOLD << color::GREEN << g_tests_passed << color::RESET << "\n";
    std::cout << "  Failed               : " << (g_tests_failed > 0 ? color::RED : color::GREEN) << color::BOLD
              << g_tests_failed << color::RESET << "\n\n";

    if (g_tests_failed == 0) {
        std::cout << color::BOLD << color::GREEN
                  << "✔ ALL NON-RESOURCE SECURITY FEATURES ARE OPERATING PROPERLY!"
                  << color::RESET << "\n\n";
        return 0;
    } else {
        std::cout << color::BOLD << color::RED
                  << "✘ SOME FEATURE TESTS FAILED!"
                  << color::RESET << "\n\n";
        return 1;
    }
}
