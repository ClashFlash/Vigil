#!/usr/bin/env python3
"""
Vigil — Architecture and Design Diagrams Generator
Generates high-resolution PNG (300 DPI) and SVG diagrams:
1. Overall System Architecture Diagram
2. Data Flow Diagram (DFD - Level 1)
3. Use-Case Diagram
4. Workflow / Activity Diagram
"""

import os
import subprocess
from pathlib import Path

DIAGRAMS_DIR = Path("docs/diagrams")
DIAGRAMS_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# 1. OVERALL SYSTEM ARCHITECTURE DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────
DOT_SYSTEM_ARCH = """
digraph SystemArchitecture {
    graph [
        rankdir=TB,
        bgcolor="#0F172A",
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=16,
        fontcolor="#F8FAFC",
        label="\\n<< VIGIL — OVERALL SYSTEM ARCHITECTURE >>\\n ",
        labelloc=t,
        nodesep=0.5,
        ranksep=0.7,
        pad=0.4,
        dpi=300
    ];

    node [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=11,
        fontcolor="#FFFFFF",
        style="filled,rounded",
        shape=rect,
        margin="0.22,0.12",
        penwidth=1.5
    ];

    edge [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=9,
        fontcolor="#94A3B8",
        color="#38BDF8",
        penwidth=1.5,
        arrowsize=0.8
    ];

    // Layer 1: Linux Host & OS
    subgraph cluster_os {
        label="HOST OPERATING SYSTEM & KERNEL SUBSYSTEMS";
        fontcolor="#94A3B8";
        fontsize=12;
        color="#334155";
        bgcolor="#1E293B";
        style="dashed,rounded";

        proc_stat [label="/proc/stat\\n(CPU ticks & per-core counters)", fillcolor="#334155", color="#64748B"];
        proc_mem  [label="/proc/meminfo\\n(RAM, buffers, cache, swap)", fillcolor="#334155", color="#64748B"];
        proc_pid  [label="/proc/[PID]/*\\n(stat, status, exe symlink, fd/*)", fillcolor="#334155", color="#64748B"];
        proc_net  [label="/proc/net/tcp, tcp6, udp, dev\\n(Active sockets & interface traffic)", fillcolor="#334155", color="#64748B"];
        auth_logs [label="/var/log/auth.log & journalctl\\n(SSH auth attempts, PAM events)", fillcolor="#334155", color="#64748B"];
        fs_paths  [label="Monitored Filesystem Paths\\n(/etc/passwd, /etc/shadow, watched dirs)", fillcolor="#334155", color="#64748B"];
    }

    // Layer 2: Ingestion & Telemetry Monitors
    subgraph cluster_monitors {
        label="VIGIL INGESTION & DATA COLLECTION ENGINES (lsm_lib)";
        fontcolor="#38BDF8";
        fontsize=12;
        color="#0284C7";
        bgcolor="#132338";
        style="rounded";

        cpu_mon  [label="CpuMonitor\\nDelta calculations & Core utilization", fillcolor="#0369A1", color="#38BDF8"];
        mem_mon  [label="MemoryMonitor\\nRAM calculation & swap metrics", fillcolor="#0369A1", color="#38BDF8"];
        proc_mon [label="ProcessMonitor\\n/proc scanner, PID sorting & FD cache", fillcolor="#0369A1", color="#38BDF8"];
        net_mon  [label="NetworkMonitor\\nHex decoders, Inode resolver & Port diff", fillcolor="#0369A1", color="#38BDF8"];
        ssh_mon  [label="SshMonitor (Worker Thread)\\nReal-time log tailer & sliding window", fillcolor="#0284C7", color="#7DD3FC"];
        fim_mon  [label="FileIntegrityMonitor (Worker Thread)\\nRFC SHA-256 hasher & recursive scanner", fillcolor="#0284C7", color="#7DD3FC"];
    }

    // Connect OS to Ingestion
    proc_stat -> cpu_mon [label="tick deltas"];
    proc_mem  -> mem_mon [label="memory bytes"];
    proc_pid  -> proc_mon [label="stat / exe readlink"];
    proc_net  -> net_mon [label="hex socket tables"];
    proc_pid  -> net_mon [label="socket inode mapping"];
    auth_logs -> ssh_mon [label="syslog / journal stream"];
    fs_paths  -> fim_mon [label="file mtime & SHA-256"];

    // Layer 3: Security Rules Engine
    subgraph cluster_rules {
        label="DETECTION & SECURITY RULES ENGINE";
        fontcolor="#F43F5E";
        fontsize=12;
        color="#E11D48";
        bgcolor="#2D1522";
        style="rounded";

        sec_engine [
            label="rules::SecurityEngine\\n(Pure Rule Evaluation + Deduplication)",
            fillcolor="#BE123C",
            color="#FB7185",
            fontsize=12,
            fontweight="bold"
        ];

        rule_tmp     [label="check_tmp_process\\n(/tmp, /dev/shm, /run/user)", fillcolor="#881337", color="#E11D48"];
        rule_del     [label="check_deleted_exe\\n(Unlinked running binary)", fillcolor="#881337", color="#E11D48"];
        rule_root    [label="check_root_suspicious\\n(UID=0 from /tmp -> CRITICAL)", fillcolor="#9F1239", color="#F43F5E"];
        rule_port    [label="check_new_listening_port\\n(Dynamic port delta)", fillcolor="#881337", color="#E11D48"];
        rule_out     [label="check_suspicious_outbound\\n(Temp process outbound socket)", fillcolor="#881337", color="#E11D48"];
        rule_dedup   [label="Alert Deduplicator\\nstd::set<pid, rule_name>", fillcolor="#4C0519", color="#BE123C"];
    }

    proc_mon -> sec_engine [label="ProcessInfo vector", color="#FB7185"];
    net_mon  -> sec_engine [label="new_ports & connections", color="#FB7185"];
    sec_engine -> rule_tmp;
    sec_engine -> rule_del;
    sec_engine -> rule_root;
    sec_engine -> rule_port;
    sec_engine -> rule_out;
    sec_engine -> rule_dedup;

    // Layer 4: Event System, Alerting & Storage
    subgraph cluster_events {
        label="EVENT DISPATCH, LOGGING & ALERTING";
        fontcolor="#34D399";
        fontsize=12;
        color="#059669";
        bgcolor="#102820";
        style="rounded";

        event_log [
            label="events::EventLog\\n(Thread-Safe In-Memory Ring Buffer, 1000 items)",
            fillcolor="#047857",
            color="#34D399",
            fontsize=12,
            fontweight="bold"
        ];

        persistent_log [
            label="Persistent Storage\\n~/.local/share/vigil/events.log (JSONL)",
            fillcolor="#064E3B",
            color="#10B981",
            shape=cylinder
        ];

        alerter [
            label="alert::Alerter (Severity Gated)\\nThreshold evaluation & alert dispatch",
            fillcolor="#047857",
            color="#34D399"
        ];

        terminal_bell [label="Terminal Bell (\\a)\\nRate-limited visible alert", fillcolor="#064E3B", color="#6EE7B7"];
        desktop_popup [label="notify-send Alert\\nDouble-fork async notification", fillcolor="#064E3B", color="#6EE7B7"];
    }

    sec_engine -> event_log [label="Security alerts", color="#F43F5E"];
    ssh_mon    -> event_log [label="Auth failure / Brute force", color="#7DD3FC"];
    fim_mon    -> event_log [label="File Created / Modified / Deleted", color="#7DD3FC"];
    net_mon    -> event_log [label="Port / Closed conn events", color="#38BDF8"];

    event_log -> persistent_log [label="Append JSON line", color="#34D399"];
    event_log -> alerter [label="on_event callback", color="#34D399"];
    alerter -> terminal_bell [label="Sev >= Bell Threshold"];
    alerter -> desktop_popup [label="Sev >= Notify Threshold"];

    // Layer 5: Presentation & User Interface
    subgraph cluster_ui {
        label="PRESENTATION LAYER (ui::Terminal TUI)";
        fontcolor="#C084FC";
        fontsize=12;
        color="#9333EA";
        bgcolor="#241335";
        style="rounded";

        ui_loop [
            label="ui::Terminal & Event Loop\\nPOSIX select() 50ms polling on STDIN",
            fillcolor="#7E22CE",
            color="#C084FC",
            fontsize=12,
            fontweight="bold"
        ];

        panel_overview [label="Overview Panel\\n(CPU per-core bars, RAM ratio)", fillcolor="#581C87", color="#A855F7"];
        panel_procs    [label="Processes Panel\\n(Sorting, Search filter, Anomaly color)", fillcolor="#581C87", color="#A855F7"];
        panel_net      [label="Network Panel\\n(Interfaces, Socket table, Rate metrics)", fillcolor="#581C87", color="#A855F7"];
        panel_events   [label="Events Panel\\n(Category filter, Keyword search, JSON feed)", fillcolor="#581C87", color="#A855F7"];
    }

    proc_mon -> ui_loop [label="Thread-safe procs_snapshot", color="#C084FC"];
    net_mon  -> ui_loop [label="Thread-safe conns_snapshot", color="#C084FC"];
    cpu_mon  -> ui_loop [label="Live CPU counters", color="#C084FC"];
    mem_mon  -> ui_loop [label="Live memory metrics", color="#C084FC"];
    event_log -> ui_loop [label="snapshot() copy", color="#C084FC"];

    ui_loop -> panel_overview;
    ui_loop -> panel_procs;
    ui_loop -> panel_net;
    ui_loop -> panel_events;

    // Operator Actor
    operator [
        label="System Administrator / Security Operator\\n(Interactive Keyboard Navigation: Tab, 1-4, /, c/m/p, Enter, q)",
        shape=ellipse,
        fillcolor="#0F766E",
        color="#2DD4BF",
        fontsize=12,
        fontweight="bold"
    ];

    operator -> ui_loop [label="Key input stream", color="#2DD4BF", penwidth=2.0];
    ui_loop -> operator [label="ANSI TrueColor 24-bit Raw Buffer", color="#C084FC", penwidth=2.0];
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# 2. DATA FLOW DIAGRAM (DFD - LEVEL 1)
# ─────────────────────────────────────────────────────────────────────────────
DOT_DFD = """
digraph DataFlowDiagram {
    graph [
        rankdir=LR,
        bgcolor="#0F172A",
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=16,
        fontcolor="#F8FAFC",
        label="\\n<< VIGIL — DATA FLOW DIAGRAM (LEVEL 1 DFD) >>\\n ",
        labelloc=t,
        nodesep=0.6,
        ranksep=0.9,
        pad=0.4,
        dpi=300
    ];

    node [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=11,
        fontcolor="#FFFFFF",
        style="filled,rounded",
        shape=rect,
        margin="0.2,0.12",
        penwidth=1.5
    ];

    edge [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=9,
        fontcolor="#94A3B8",
        color="#38BDF8",
        penwidth=1.5,
        arrowsize=0.8
    ];

    // External Entities
    subgraph cluster_entities {
        label="EXTERNAL ENTITIES";
        fontcolor="#CBD5E1";
        fontsize=11;
        color="#334155";
        bgcolor="#1E293B";
        style="dashed";

        ent_kernel   [label="[External Entity]\\nLinux Kernel & Procfs", fillcolor="#475569", color="#94A3B8", shape=box];
        ent_syslog   [label="[External Entity]\\nAuth Logs & Journald", fillcolor="#475569", color="#94A3B8", shape=box];
        ent_user     [label="[External Entity]\\nSecurity Operator", fillcolor="#0D9488", color="#2DD4BF", shape=box];
        ent_notify   [label="[External Entity]\\nDesktop Notification Daemon", fillcolor="#475569", color="#94A3B8", shape=box];
    }

    // Data Stores
    subgraph cluster_stores {
        label="DATA STORES";
        fontcolor="#34D399";
        fontsize=11;
        color="#065F46";
        bgcolor="#064E3B";
        style="dashed";

        store_cfg     [label="D1 | Config Files\\n(thresholds & monitored_files)", shape=record, fillcolor="#047857", color="#6EE7B7"];
        store_base    [label="D2 | Baselines Cache\\n(FIM Hashes & Startup Ports)", shape=record, fillcolor="#047857", color="#6EE7B7"];
        store_events  [label="D3 | In-Memory Ring Buffer\\n(Last 1,000 Events)", shape=record, fillcolor="#047857", color="#6EE7B7"];
        store_disklog [label="D4 | Persistent Event Log\\n(~/.local/share/vigil/events.log)", shape=record, fillcolor="#047857", color="#6EE7B7"];
    }

    // Processes
    p1 [label="1.0 Ingest System Telemetry\\n(CPU, RAM, /proc parser)", fillcolor="#1E40AF", color="#60A5FA", shape=ellipse];
    p2 [label="2.0 Correlate Network Sockets\\n(Hex decode, Inode mapping)", fillcolor="#1E40AF", color="#60A5FA", shape=ellipse];
    p3 [label="3.0 Monitor File Integrity\\n(SHA-256 diff vs baseline)", fillcolor="#1E40AF", color="#60A5FA", shape=ellipse];
    p4 [label="4.0 Analyze SSH Activity\\n(Regex parse & brute-force tracker)", fillcolor="#1E40AF", color="#60A5FA", shape=ellipse];
    p5 [label="5.0 Evaluate Security Rules\\n(Anomaly matching & deduplication)", fillcolor="#BE123C", color="#FB7185", shape=ellipse];
    p6 [label="6.0 Dispatch Alerts & Log\\n(Threshold gate, JSONL format)", fillcolor="#047857", color="#34D399", shape=ellipse];
    p7 [label="7.0 Render Dashboard UI\\n(Snapshots, Sort, Filter & Key Input)", fillcolor="#6B21A8", color="#C084FC", shape=ellipse];

    // Data Flows
    store_cfg -> p1 [label="monitored paths"];
    store_cfg -> p6 [label="alert thresholds"];

    ent_kernel -> p1 [label="raw /proc counters"];
    ent_kernel -> p2 [label="/proc/net tables & fd inodes"];
    ent_kernel -> p3 [label="file mtime & contents"];
    ent_syslog -> p4 [label="auth log lines"];

    p3 -> store_base [label="initial file hashes"];
    store_base -> p3 [label="baseline compare"];

    p2 -> store_base [label="initial listening ports"];
    store_base -> p2 [label="baseline compare"];

    p1 -> p5 [label="ProcessInfo list"];
    p2 -> p5 [label="new ports & active sockets"];

    p5 -> p6 [label="security alerts"];
    p3 -> p6 [label="file tampering events"];
    p4 -> p6 [label="auth & brute force events"];
    p2 -> p6 [label="port & connection events"];

    p6 -> store_events [label="push Event"];
    p6 -> store_disklog [label="write JSONL record"];
    p6 -> ent_notify [label="desktop notification popup"];

    store_events -> p7 [label="snapshot() copy"];
    p1 -> p7 [label="CPU, RAM & procs snapshot"];
    p2 -> p7 [label="connections snapshot"];

    ent_user -> p7 [label="keystrokes (search, sort, tab)"];
    p7 -> ent_user [label="ANSI terminal frames"];
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# 3. USE-CASE DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────
DOT_USE_CASE = """
digraph UseCaseDiagram {
    graph [
        rankdir=LR,
        bgcolor="#0F172A",
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=16,
        fontcolor="#F8FAFC",
        label="\\n<< VIGIL — SECURITY & MONITORING USE-CASE DIAGRAM >>\\n ",
        labelloc=t,
        nodesep=0.4,
        ranksep=0.8,
        pad=0.4,
        dpi=300
    ];

    node [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=10,
        fontcolor="#FFFFFF",
        style="filled",
        penwidth=1.5
    ];

    edge [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=8,
        fontcolor="#94A3B8",
        color="#38BDF8",
        penwidth=1.3,
        arrowsize=0.7
    ];

    // Actors
    actor_admin [
        label="Security Operator /\\nSystem Administrator",
        shape=circle,
        width=1.6,
        fillcolor="#0D9488",
        color="#2DD4BF",
        fontsize=11,
        fontweight="bold"
    ];

    actor_attacker [
        label="External Attacker /\\nMalicious Process",
        shape=circle,
        width=1.6,
        fillcolor="#991B1B",
        color="#F87171",
        fontsize=11,
        fontweight="bold"
    ];

    // Use Cases Subgraph
    subgraph cluster_vigil_boundary {
        label="VIGIL APPLICATION BOUNDARY";
        fontcolor="#38BDF8";
        fontsize=13;
        color="#0284C7";
        bgcolor="#1E293B";
        style="rounded,dashed";

        node [shape=ellipse, fillcolor="#1E3A8A", color="#38BDF8", margin="0.15,0.08"];

        uc_overview     [label="View System Resource Overview\\n(Per-core CPU & RAM Usage)"];
        uc_proc_table   [label="Monitor & Filter Processes\\n(Search by name, sort c/m/p)"];
        uc_proc_detail  [label="Inspect Process File Descriptors\\n(Live FD count inspection)"];
        uc_net_conn     [label="Inspect Network Activity\\n(Active TCP/UDP sockets & Rates)"];
        uc_detect_tmp   [label="Detect Suspicious Path Execution\\n(/tmp, /dev/shm, /run/user)"];
        uc_detect_del   [label="Detect Deleted Running Binaries\\n(/proc/[PID]/exe deleted)"];
        uc_detect_root  [label="Detect Suspicious Root Escalation\\n(UID=0 from /tmp -> CRITICAL)"];
        uc_detect_ports [label="Detect Newly Bound Listening Ports\\n(Dynamic comparison vs baseline)"];
        uc_detect_out   [label="Detect Suspicious Outbound Connection\\n(Temp process outbound socket)"];
        uc_fim          [label="Monitor Critical File Integrity\\n(Detect Creation/Modification/Deletion)"];
        uc_ssh_fail     [label="Detect SSH Auth Failures\\n(Failed password & invalid user)"];
        uc_ssh_brute    [label="Detect SSH Brute-Force Attacks\\n(Sliding time-window threshold)"];
        uc_event_search [label="Search & Filter Event History\\n(Category filter & full-text query)"];
        uc_alert_notify [label="Receive Audio & Desktop Alerts\\n(Terminal bell & notify-send)"];
    }

    // Actor Connections
    actor_admin -> uc_overview;
    actor_admin -> uc_proc_table;
    actor_admin -> uc_net_conn;
    actor_admin -> uc_event_search;
    actor_admin -> uc_alert_notify [dir=back, label="notified by"];

    uc_proc_table -> uc_proc_detail [label="<<extend>>", style="dashed", color="#A855F7"];

    // Threat Interactions
    actor_attacker -> uc_detect_tmp   [label="spawns malware", color="#F87171", style="dashed"];
    actor_attacker -> uc_detect_del   [label="unlinks binary", color="#F87171", style="dashed"];
    actor_attacker -> uc_detect_root  [label="privilege escalation", color="#F87171", style="dashed"];
    actor_attacker -> uc_detect_ports [label="binds listener", color="#F87171", style="dashed"];
    actor_attacker -> uc_detect_out   [label="C2 outbound", color="#F87171", style="dashed"];
    actor_attacker -> uc_fim          [label="tampers /etc files", color="#F87171", style="dashed"];
    actor_attacker -> uc_ssh_fail     [label="credential guess", color="#F87171", style="dashed"];
    actor_attacker -> uc_ssh_brute    [label="brute-force burst", color="#F87171", style="dashed"];

    // Extensions & Inclusions
    uc_detect_tmp   -> uc_alert_notify [label="<<include>>", style="dashed", color="#34D399"];
    uc_detect_del   -> uc_alert_notify [label="<<include>>", style="dashed", color="#34D399"];
    uc_detect_root  -> uc_alert_notify [label="<<include>>", style="dashed", color="#34D399"];
    uc_detect_ports -> uc_alert_notify [label="<<include>>", style="dashed", color="#34D399"];
    uc_detect_out   -> uc_alert_notify [label="<<include>>", style="dashed", color="#34D399"];
    uc_fim          -> uc_alert_notify [label="<<include>>", style="dashed", color="#34D399"];
    uc_ssh_brute    -> uc_alert_notify [label="<<include>>", style="dashed", color="#34D399"];
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# 4. WORKFLOW / ACTIVITY DIAGRAM
# ─────────────────────────────────────────────────────────────────────────────
DOT_WORKFLOW = """
digraph WorkflowActivity {
    graph [
        rankdir=TB,
        bgcolor="#0F172A",
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=16,
        fontcolor="#F8FAFC",
        label="\\n<< VIGIL — RUNTIME WORKFLOW & ACTIVITY DIAGRAM >>\\n ",
        labelloc=t,
        nodesep=0.4,
        ranksep=0.6,
        pad=0.4,
        dpi=300
    ];

    node [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=10,
        fontcolor="#FFFFFF",
        style="filled,rounded",
        shape=rect,
        margin="0.18,0.1",
        penwidth=1.5
    ];

    edge [
        fontname="Helvetica Neue, Arial, sans-serif",
        fontsize=9,
        fontcolor="#94A3B8",
        color="#38BDF8",
        penwidth=1.5,
        arrowsize=0.8
    ];

    start_node [label="Start Vigil Application", shape=circle, fillcolor="#10B981", color="#6EE7B7", width=1.3, fontweight="bold"];

    subgraph cluster_init {
        label="INITIALIZATION PHASE";
        fontcolor="#38BDF8";
        fontsize=11;
        color="#0284C7";
        bgcolor="#1E293B";
        style="rounded,dashed";

        step_sig    [label="Install Signal Handlers\\n(SIGINT & SIGTERM -> g_shutdown_cv)", fillcolor="#1E3A8A", color="#60A5FA"];
        step_cfg    [label="Load AppConfig & Thresholds\\n(config/thresholds.conf & monitored_files.conf)", fillcolor="#1E3A8A", color="#60A5FA"];
        step_log    [label="Initialize EventLog & Alerter\\n(Ring buffer & persistent JSONL path)", fillcolor="#1E3A8A", color="#60A5FA"];
        step_base   [label="Establish Baselines\\n(Initial network listening ports & FIM SHA-256)", fillcolor="#1E3A8A", color="#60A5FA"];
        step_thread [label="Launch Worker Threads\\n(SshMonitor thread & FileIntegrityMonitor thread)", fillcolor="#1E3A8A", color="#60A5FA"];
    }

    start_node -> step_sig -> step_cfg -> step_log -> step_base -> step_thread;

    // Concurrency Fork
    fork_node [label="Concurrent Execution Fork", shape=record, fillcolor="#0284C7", color="#38BDF8", height=0.15, width=4.0];
    step_thread -> fork_node;

    // Concurrent Pipeline 1: Data Thread
    subgraph cluster_data_pipe {
        label="DATA COLLECTION & SECURITY ENGINE (2s Cycle)";
        fontcolor="#FB7185";
        fontsize=11;
        color="#E11D48";
        bgcolor="#24131D";
        style="rounded";

        d_refresh [label="Refresh Hardware & OS State\\n(proc_mon, net_mon, cpu_mon, mem_mon)", fillcolor="#9F1239", color="#F43F5E"];
        d_correlate [label="Correlate Inodes to PIDs\\n(Resolve /proc/[PID]/fd socket links)", fillcolor="#9F1239", color="#F43F5E"];
        d_eval [label="Evaluate Security Rules\\n(Tmp paths, deleted exe, root check, new ports)", fillcolor="#BE123C", color="#FB7185", fontweight="bold"];
        d_decision [label="Anomaly\\nDetected?", shape=diamond, fillcolor="#881337", color="#E11D48"];
        d_push [label="Deduplicate & Push Event\\n(Emit to EventLog & trigger Alerter)", fillcolor="#BE123C", color="#FB7185"];
        d_sleep [label="Sleep 2s\\n(wait on g_shutdown_cv)", fillcolor="#9F1239", color="#F43F5E"];
    }

    fork_node -> d_refresh [color="#FB7185"];
    d_refresh -> d_correlate -> d_eval -> d_decision;
    d_decision -> d_push [label="Yes", color="#F43F5E"];
    d_decision -> d_sleep [label="No", color="#94A3B8"];
    d_push -> d_sleep;
    d_sleep -> d_refresh [label="Loop while g_running", color="#FB7185", style="dashed"];

    // Concurrent Pipeline 2: FIM Thread
    subgraph cluster_fim_pipe {
        label="FILE INTEGRITY WORKER (10s Cycle)";
        fontcolor="#34D399";
        fontsize=11;
        color="#059669";
        bgcolor="#0F241A";
        style="rounded";

        f_scan [label="Recursive Directory Scan\\n(Collect regular files & mtime)", fillcolor="#065F46", color="#34D399"];
        f_hash [label="Compute SHA-256 for Modified Files\\n(Skip hashing if size/mtime match)", fillcolor="#065F46", color="#34D399"];
        f_check [label="File Tampered,\\nCreated or Deleted?", shape=diamond, fillcolor="#047857", color="#10B981"];
        f_emit [label="Emit FIM Event\\n(Category::FILE with hash diff)", fillcolor="#047857", color="#34D399"];
        f_wait [label="Sleep 10s\\n(wait on cv_)", fillcolor="#065F46", color="#34D399"];
    }

    fork_node -> f_scan [color="#34D399"];
    f_scan -> f_hash -> f_check;
    f_check -> f_emit [label="Yes", color="#34D399"];
    f_check -> f_wait [label="No", color="#94A3B8"];
    f_emit -> f_wait;
    f_wait -> f_scan [label="Loop while running_", color="#34D399", style="dashed"];

    // Concurrent Pipeline 3: SSH Monitor
    subgraph cluster_ssh_pipe {
        label="SSH AUTH MONITOR (Continuous)";
        fontcolor="#38BDF8";
        fontsize=11;
        color="#0284C7";
        bgcolor="#132338";
        style="rounded";

        s_tail [label="Tail auth.log / journalctl\\n(Stream lines in real-time)", fillcolor="#0369A1", color="#38BDF8"];
        s_parse [label="Regex Extract Type, User & IP\\n(Accepted, Failed, Invalid User)", fillcolor="#0369A1", color="#38BDF8"];
        s_brute [label="Window Failures >=\\nThreshold?", shape=diamond, fillcolor="#0284C7", color="#7DD3FC"];
        s_alarm [label="Emit SSH Brute Force Alert\\n(Category::AUTH, HIGH Severity)", fillcolor="#0284C7", color="#7DD3FC"];
    }

    fork_node -> s_tail [color="#38BDF8"];
    s_tail -> s_parse -> s_brute;
    s_brute -> s_alarm [label="Yes", color="#7DD3FC"];
    s_brute -> s_tail [label="No", color="#94A3B8"];
    s_alarm -> s_tail;

    // Concurrent Pipeline 4: UI Event Loop
    subgraph cluster_ui_pipe {
        label="INTERACTIVE TUI EVENT LOOP (50ms select)";
        fontcolor="#C084FC";
        fontsize=11;
        color="#9333EA";
        bgcolor="#231330";
        style="rounded";

        u_snapshot [label="Capture Local Snapshots\\n(Thread-safe copy of procs & conns)", fillcolor="#6B21A8", color="#C084FC"];
        u_render   [label="Draw Double-Buffered ANSI TUI\\n(Overview, Procs, Network, Events)", fillcolor="#6B21A8", color="#C084FC"];
        u_select   [label="select() on STDIN (50ms)\\n(Non-blocking input multiplexer)", fillcolor="#7E22CE", color="#C084FC"];
        u_key_dec  [label="Key Pressed?", shape=diamond, fillcolor="#581C87", color="#9333EA"];
        u_handle   [label="Handle Navigation / Sort / Search\\n(Tab, 1-4, c/m/p, /, Enter)", fillcolor="#6B21A8", color="#C084FC"];
    }

    fork_node -> u_snapshot [color="#C084FC"];
    u_snapshot -> u_render -> u_select -> u_key_dec;
    u_key_dec -> u_handle [label="Yes", color="#C084FC"];
    u_key_dec -> u_snapshot [label="No / Timeout", color="#94A3B8"];
    u_handle -> u_snapshot [label="Continue loop", style="dashed", color="#C084FC"];

    // Teardown
    join_node [label="Graceful Shutdown & Resource Teardown\\n(q pressed OR SIGINT/SIGTERM -> Join Threads -> Restore Terminal)", shape=box, fillcolor="#B91C1C", color="#F87171", fontweight="bold"];
    end_node [label="Clean Exit (0)", shape=circle, fillcolor="#10B981", color="#6EE7B7", width=1.1, fontweight="bold"];

    u_handle -> join_node [label="User pressed 'q'", color="#F87171"];
    join_node -> end_node;
}
"""

def generate_diagram(name, dot_src):
    dot_file = DIAGRAMS_DIR / f"{name}.dot"
    svg_file = DIAGRAMS_DIR / f"{name}.svg"
    png_file = DIAGRAMS_DIR / f"{name}.png"

    dot_file.write_text(dot_src.strip())
    print(f"Generating {name}...")

    # Render SVG
    subprocess.run(["dot", "-Tsvg", str(dot_file), "-o", str(svg_file)], check=True)
    # Render High-Res PNG (300 DPI)
    subprocess.run(["dot", "-Tpng", "-Gdpi=300", str(dot_file), "-o", str(png_file)], check=True)
    print(f"  ✔ Generated: {svg_file} & {png_file}")

def main():
    generate_diagram("1_system_architecture", DOT_SYSTEM_ARCH)
    generate_diagram("2_data_flow_diagram", DOT_DFD)
    generate_diagram("3_use_case_diagram", DOT_USE_CASE)
    generate_diagram("4_workflow_activity_diagram", DOT_WORKFLOW)
    print("\nAll diagrams successfully generated in docs/diagrams/")

if __name__ == "__main__":
    main()
