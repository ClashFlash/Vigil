#!/usr/bin/env python3
"""
Vigil — Interactive Security Event Simulator & Showcase Menu

This script allows you to inject real security anomalies, network events,
file integrity tampering, and SSH authentication attacks into the system
one at a time so you can observe Vigil detecting and displaying them in real-time.

Rule: ONLY ONE EVENT RUNS AT A TIME.
When you select a new event, the previous running event and its processes,
sockets, or temp files are automatically terminated and cleaned up.
"""

import os
import sys
import time
import signal
import socket
import shutil
import atexit
import subprocess
from pathlib import Path

# ANSI colors
class Style:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[38;2;255;95;86m"
    GREEN   = "\033[38;2;40;210;120m"
    YELLOW  = "\033[38;2;255;215;0m"
    BLUE    = "\033[38;2;90;150;255m"
    MAGENTA = "\033[38;2;240;110;220m"
    CYAN    = "\033[38;2;80;230;240m"
    WHITE   = "\033[38;2;250;250;250m"
    BG_BLUE = "\033[48;2;25;50;100m"

class ScenarioManager:
    def __init__(self):
        self.current_id = None
        self.current_title = "None (Idle)"
        self.active_procs = []      # list of subprocess.Popen
        self.active_sockets = []    # list of socket.socket
        self.active_paths = []      # list of Path
        self.monitored_dir = Path("/tmp/vigil_monitored")
        self.auth_log_path = Path("/tmp/vigil_auth.log")

        # Ensure base directories exist
        self.monitored_dir.mkdir(parents=True, exist_ok=True)
        if not self.auth_log_path.exists():
            self.auth_log_path.touch()

    def stop_current(self):
        """Kills any active process, closes sockets, and removes temp files."""
        if self.current_id is None and not self.active_procs and not self.active_sockets:
            return

        print(f"\n{Style.YELLOW}🛑 Stopping and cleaning up previous event: [{self.current_id}] {self.current_title}...{Style.RESET}")

        # Kill processes
        for p in self.active_procs:
            try:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=1.0)
                print(f"   {Style.DIM}Killed PID {p.pid}{Style.RESET}")
            except Exception as e:
                print(f"   {Style.DIM}Process cleanup notice: {e}{Style.RESET}")
        self.active_procs.clear()

        # Close sockets
        for s in self.active_sockets:
            try:
                s.close()
                print(f"   {Style.DIM}Closed listening socket{Style.RESET}")
            except Exception as e:
                pass
        self.active_sockets.clear()

        # Remove temp files registered for the scenario
        for path in self.active_paths:
            try:
                if path.is_file() or path.is_symlink():
                    path.unlink(missing_ok=True)
                    print(f"   {Style.DIM}Removed file: {path}{Style.RESET}")
                elif path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                    print(f"   {Style.DIM}Removed dir: {path}{Style.RESET}")
            except Exception as e:
                pass
        self.active_paths.clear()

        self.current_id = None
        self.current_title = "None (Idle)"
        print(f"{Style.GREEN}✔ System restored to clean state.{Style.RESET}\n")

    def check_vigil_running(self):
        """Checks if Vigil dashboard binary is running."""
        try:
            out = subprocess.check_output(["pgrep", "-x", "vigil"], text=True).strip().splitlines()
            my_pid = os.getpid()
            vigil_pids = [p for p in out if int(p) != my_pid]
            return vigil_pids
        except subprocess.CalledProcessError:
            return []

    # ─────────────────────────────────────────────────────────────────────────
    # SCENARIOS
    # ─────────────────────────────────────────────────────────────────────────

    def run_scenario_1_tmp_process(self):
        """Process running from /tmp directory."""
        self.stop_current()
        self.current_id = 1
        self.current_title = "Process running from /tmp directory (HIGH Severity)"

        target_bin = Path("/tmp") / "vigil_evil_miner"
        shutil.copy2("/bin/sleep", target_bin)
        target_bin.chmod(0o755)
        self.active_paths.append(target_bin)

        proc = subprocess.Popen([str(target_bin), "3600"])
        self.active_procs.append(proc)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [1]: Process in /tmp{Style.RESET}")
        print(f"   • Executable : {Style.CYAN}{target_bin}{Style.RESET}")
        print(f"   • PID        : {Style.BOLD}{proc.pid}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. Switch to Vigil terminal.")
        print(f"   2. In {Style.BOLD}Processes{Style.RESET} panel (key '2' or Tab):")
        print(f"      PID {proc.pid} ({target_bin.name}) will be highlighted in {Style.RED}RED{Style.RESET} as anomalous.")
        print(f"   3. In {Style.BOLD}Events{Style.RESET} panel (key '4' or Tab):")
        print(f"      You will see {Style.RED}[HIGH] Process executing from temp directory{Style.RESET}")
        print(f"      Details: 'PID {proc.pid} running from /tmp/vigil_evil_miner'")

    def run_scenario_2_shm_process(self):
        """Process running from /dev/shm."""
        self.stop_current()
        self.current_id = 2
        self.current_title = "Process running from /dev/shm (Shared Memory) (HIGH Severity)"

        target_bin = Path("/dev/shm") / "vigil_shm_payload"
        shutil.copy2("/bin/sleep", target_bin)
        target_bin.chmod(0o755)
        self.active_paths.append(target_bin)

        proc = subprocess.Popen([str(target_bin), "3600"])
        self.active_procs.append(proc)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [2]: Process in /dev/shm{Style.RESET}")
        print(f"   • Executable : {Style.CYAN}{target_bin}{Style.RESET}")
        print(f"   • PID        : {Style.BOLD}{proc.pid}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Processes{Style.RESET} panel: PID {proc.pid} is highlighted as anomalous (/dev/shm origin).")
        print(f"   2. In {Style.BOLD}Events{Style.RESET} panel: {Style.RED}[HIGH] Process executing from temp directory{Style.RESET}.")

    def run_scenario_3_deleted_exe(self):
        """Running process with deleted binary."""
        self.stop_current()
        self.current_id = 3
        self.current_title = "Process running with deleted executable (HIGH Severity)"

        target_bin = Path("/tmp") / "vigil_ghost_agent"
        shutil.copy2("/bin/sleep", target_bin)
        target_bin.chmod(0o755)

        proc = subprocess.Popen([str(target_bin), "3600"])
        self.active_procs.append(proc)
        time.sleep(0.1)

        # Delete the binary from disk while it is actively running
        target_bin.unlink(missing_ok=True)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [3]: Process with (deleted) executable{Style.RESET}")
        print(f"   • Spawned PID {proc.pid} and deleted binary from disk.")
        print(f"   • /proc/{proc.pid}/exe link: {Style.CYAN}{os.readlink(f'/proc/{proc.pid}/exe')}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Processes{Style.RESET} panel: PID {proc.pid} shows '(deleted)' suffix and red highlight.")
        print(f"   2. In {Style.BOLD}Events{Style.RESET} panel: {Style.RED}[HIGH] Running process with deleted executable{Style.RESET}.")

    def run_scenario_4_new_listen_port(self):
        """Open a new listening TCP port."""
        self.stop_current()
        self.current_id = 4
        self.current_title = "New listening TCP port opened (MEDIUM Severity)"

        port = 4444
        # Spawn python HTTP server as a mock backdoor listening on port 4444
        proc = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.active_procs.append(proc)
        time.sleep(0.2)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [4]: New listening port opened{Style.RESET}")
        print(f"   • Port       : {Style.BOLD}{Style.CYAN}127.0.0.1:{port}{Style.RESET}")
        print(f"   • PID        : {Style.BOLD}{proc.pid}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Network{Style.RESET} panel (key '3' or Tab):")
        print(f"      Port {port} appears in the listening connections list.")
        print(f"   2. In {Style.BOLD}Events{Style.RESET} panel (key '4' or Tab):")
        print(f"      {Style.YELLOW}[MEDIUM] New listening port detected: Port {port}{Style.RESET}")
        print(f"      {Style.YELLOW}[MEDIUM] Process opened new listening port{Style.RESET}")

    def run_scenario_5_suspicious_outbound(self):
        """Suspicious outbound connection from a process in /tmp."""
        self.stop_current()
        self.current_id = 5
        self.current_title = "Suspicious outbound connection from temp process (HIGH Severity)"

        listen_port = 9999
        # 1. Spawn a local receiver
        receiver = subprocess.Popen(
            [sys.executable, "-c",
             f"import socket, time; s = socket.socket(); s.bind(('127.0.0.1', {listen_port})); s.listen(1); conn, _ = s.accept(); time.sleep(3600)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.active_procs.append(receiver)
        time.sleep(0.15)

        # 2. Build a tiny C client in /tmp that connects to port 9999
        client_c = Path("/tmp") / "vigil_c2_client.c"
        client_bin = Path("/tmp") / "vigil_c2_client"
        client_c.write_text(f"""
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
int main() {{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {{0}};
    a.sin_family = AF_INET;
    a.sin_port = htons({listen_port});
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    connect(s, (struct sockaddr*)&a, sizeof(a));
    sleep(3600);
    return 0;
}}
""")
        subprocess.run(["gcc", "-O2", str(client_c), "-o", str(client_bin)], check=True)
        client_c.unlink(missing_ok=True)
        self.active_paths.append(client_bin)

        client_proc = subprocess.Popen([str(client_bin)])
        self.active_procs.append(client_proc)
        time.sleep(0.1)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [5]: Outbound connection from /tmp process{Style.RESET}")
        print(f"   • Client exe : {Style.CYAN}{client_bin}{Style.RESET} (PID {client_proc.pid})")
        print(f"   • Outbound to: {Style.CYAN}127.0.0.1:{listen_port}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Network{Style.RESET} panel: Active connection ESTABLISHED between PID {client_proc.pid} and port {listen_port}.")
        print(f"   2. In {Style.BOLD}Events{Style.RESET} panel: {Style.RED}[HIGH] Suspicious outbound connection{Style.RESET}.")

    def run_scenario_6_fim_create(self):
        """FIM: Create file in monitored path."""
        self.stop_current()
        self.current_id = 6
        self.current_title = "FIM: Create new file in monitored directory (MEDIUM Severity)"

        target = self.monitored_dir / "backdoor_service.conf"
        target.write_text("[Service]\nExecStart=/tmp/evil_miner\nRestart=always\n")
        self.active_paths.append(target)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [6]: File Created in Monitored Directory{Style.RESET}")
        print(f"   • File path: {Style.CYAN}{target}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Events{Style.RESET} panel (within 10 seconds of FIM scan interval):")
        print(f"      {Style.YELLOW}[MEDIUM] File CREATED: backdoor_service.conf{Style.RESET}")
        print(f"      Details will display full path and computed SHA-256 hash.")

    def run_scenario_7_fim_modify(self):
        """FIM: Modify existing monitored file."""
        self.stop_current()
        self.current_id = 7
        self.current_title = "FIM: Tamper / modify monitored file (HIGH Severity)"

        target = self.monitored_dir / "backdoor_service.conf"
        # Create first if not present
        if not target.exists():
            target.write_text("ORIGINAL_CONTENT=SECURE\n")
            time.sleep(1.0) # Let baseline capture it

        # Now tamper with it
        time.sleep(0.1)
        target.write_text("MODIFIED_CONTENT=EXPLOITED_HASH_TAMPERED\nATTACKER=198.51.100.99\n")
        self.active_paths.append(target)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [7]: File Modified (Tampered){Style.RESET}")
        print(f"   • File path: {Style.CYAN}{target}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Events{Style.RESET} panel (within next 10s FIM scan interval):")
        print(f"      {Style.RED}[HIGH] File MODIFIED: backdoor_service.conf{Style.RESET}")
        print(f"      Details will show: 'Old: <hash>... -> New: <hash>...'.")

    def run_scenario_8_fim_delete(self):
        """FIM: Delete monitored file."""
        self.stop_current()
        self.current_id = 8
        self.current_title = "FIM: Delete monitored file (HIGH Severity)"

        target = self.monitored_dir / "backdoor_service.conf"
        target.unlink(missing_ok=True)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [8]: File Deleted{Style.RESET}")
        print(f"   • Removed: {Style.CYAN}{target}{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Events{Style.RESET} panel (within next 10s FIM scan interval):")
        print(f"      {Style.RED}[HIGH] File DELETED: backdoor_service.conf{Style.RESET}")

    def inject_ssh_line(self, line):
        """Appends log line to /tmp/vigil_auth.log and broadcasts via logger."""
        with open(self.auth_log_path, "a") as f:
            f.write(line + "\n")
            f.flush()
        # Also send via system logger (tag sshd)
        subprocess.run(["logger", "-t", "sshd", line], check=False)

    def run_scenario_9_ssh_fail(self):
        """SSH: Single failed password attempt."""
        self.stop_current()
        self.current_id = 9
        self.current_title = "SSH: Single failed password attempt (MEDIUM Severity)"

        attacker_ip = "198.51.100.23"
        ts = time.strftime("%b %d %H:%M:%S")
        log_line = f"{ts} server sshd[12001]: Failed password for root from {attacker_ip} port 45212 ssh2"
        self.inject_ssh_line(log_line)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [9]: SSH Failed Login Attempt{Style.RESET}")
        print(f"   • Attacker IP: {Style.CYAN}{attacker_ip}{Style.RESET}")
        print(f"   • User       : {Style.BOLD}root{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Events{Style.RESET} panel (key '4' or Tab):")
        print(f"      {Style.YELLOW}[MEDIUM] SSH authentication failure{Style.RESET}")
        print(f"      Details: 'User: root  from: {attacker_ip}'")

    def run_scenario_10_ssh_invalid(self):
        """SSH: Invalid user login attempt."""
        self.stop_current()
        self.current_id = 10
        self.current_title = "SSH: Invalid user account attempt (MEDIUM Severity)"

        attacker_ip = "203.0.113.44"
        ts = time.strftime("%b %d %H:%M:%S")
        log_line = f"{ts} server sshd[12002]: Invalid user guest_intruder from {attacker_ip} port 38910"
        self.inject_ssh_line(log_line)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [10]: SSH Invalid User Login{Style.RESET}")
        print(f"   • Attacker IP: {Style.CYAN}{attacker_ip}{Style.RESET}")
        print(f"   • User       : {Style.BOLD}guest_intruder{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Events{Style.RESET} panel:")
        print(f"      {Style.YELLOW}[MEDIUM] SSH authentication failure{Style.RESET}")
        print(f"      Details: 'User: guest_intruder  from: {attacker_ip}'")

    def run_scenario_11_ssh_success(self):
        """SSH: Successful login."""
        self.stop_current()
        self.current_id = 11
        self.current_title = "SSH: Successful login (LOW Severity)"

        user_ip = "192.168.1.105"
        ts = time.strftime("%b %d %H:%M:%S")
        log_line = f"{ts} server sshd[12003]: Accepted password for deployer from {user_ip} port 55120 ssh2"
        self.inject_ssh_line(log_line)

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Started Event [11]: SSH Successful Login{Style.RESET}")
        print(f"   • IP  : {Style.CYAN}{user_ip}{Style.RESET}")
        print(f"   • User: {Style.BOLD}deployer{Style.RESET}")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Events{Style.RESET} panel:")
        print(f"      {Style.CYAN}[LOW] SSH login successful{Style.RESET}")
        print(f"      Details: 'User: deployer  from: {user_ip}'")

    def run_scenario_12_ssh_brute_force(self):
        """SSH: Rapid brute force attack."""
        self.stop_current()
        self.current_id = 12
        self.current_title = "SSH: Brute-Force Attack Simulation (HIGH Severity)"

        attacker_ip = "203.0.113.88"
        usernames = ["root", "admin", "test", "oracle", "postgres", "ubuntu"]

        print(f"\n{Style.BOLD}{Style.GREEN}🚀 Launching Event [12]: SSH Brute Force Attack ({len(usernames)} rapid attempts)...{Style.RESET}")
        for i, u in enumerate(usernames):
            ts = time.strftime("%b %d %H:%M:%S")
            line = f"{ts} server sshd[{12100 + i}]: Failed password for {u} from {attacker_ip} port {40000 + i} ssh2"
            self.inject_ssh_line(line)
            time.sleep(0.05)

        print(f"   • Attacker IP : {Style.CYAN}{attacker_ip}{Style.RESET}")
        print(f"   • Attempts    : {len(usernames)} failed logins injected within 1 second.")
        print(f"\n{Style.BOLD}{Style.MAGENTA}👉 What to observe in Vigil:{Style.RESET}")
        print(f"   1. In {Style.BOLD}Events{Style.RESET} panel (key '4' or Tab):")
        print(f"      Multiple failure events, culminating immediately in:")
        print(f"      {Style.RED}[HIGH] SSH brute force detected{Style.RESET}")
        print(f"      Details: '{attacker_ip} made 6 failed attempts in 60s'")
        print(f"   2. Terminal bell (sound) or desktop notification will fire!")

def print_banner(manager):
    vigil_pids = manager.check_vigil_running()
    print("\033[2J\033[H", end="") # Clear terminal
    line = "═" * 78
    print(f"{Style.BOLD}{Style.CYAN}╔{line}╗{Style.RESET}")
    print(f"{Style.BOLD}{Style.CYAN}║{Style.RESET} {Style.BOLD}{Style.WHITE}VIGIL — SECURITY EVENT SIMULATOR & DEMONSTRATION CONTROL PANEL{Style.RESET}     {Style.BOLD}{Style.CYAN}║{Style.RESET}")
    print(f"{Style.BOLD}{Style.CYAN}╚{line}╝{Style.RESET}")

    if vigil_pids:
        vigil_status = f"{Style.GREEN}● RUNNING (PID: {', '.join(vigil_pids)}){Style.RESET}"
    else:
        vigil_status = f"{Style.YELLOW}○ NOT RUNNING (run './build/release/vigil' in another terminal){Style.RESET}"

    print(f"  Vigil Status       : {vigil_status}")
    if manager.current_id is not None:
        active_status = f"{Style.BOLD}{Style.GREEN}[Event {manager.current_id}] {manager.current_title}{Style.RESET}"
    else:
        active_status = f"{Style.DIM}None (Idle - no active events){Style.RESET}"
    print(f"  Currently Active   : {active_status}")
    print(f"  Rule               : {Style.DIM}Only 1 event runs at a time. Selecting a new event kills the prior one.{Style.RESET}")
    print(f"{Style.CYAN}─{Style.RESET}" * 80)

def print_menu():
    print(f"\n  {Style.BOLD}{Style.BLUE}PROCESS ANOMALIES & EXECUTION RULES:{Style.RESET}")
    print(f"   {Style.BOLD}1{Style.RESET}) Process executing from /tmp directory           {Style.RED}[HIGH]{Style.RESET}")
    print(f"   {Style.BOLD}2{Style.RESET}) Process executing from /dev/shm (shared memory)  {Style.RED}[HIGH]{Style.RESET}")
    print(f"   {Style.BOLD}3{Style.RESET}) Process running with deleted executable (ghost) {Style.RED}[HIGH]{Style.RESET}")

    print(f"\n  {Style.BOLD}{Style.BLUE}NETWORK ANOMALIES & SOCKETS:{Style.RESET}")
    print(f"   {Style.BOLD}4{Style.RESET}) Open new listening TCP port (port 4444)         {Style.YELLOW}[MEDIUM]{Style.RESET}")
    print(f"   {Style.BOLD}5{Style.RESET}) Suspicious outbound connection from /tmp proc   {Style.RED}[HIGH]{Style.RESET}")

    print(f"\n  {Style.BOLD}{Style.BLUE}FILE INTEGRITY MONITOR (FIM):{Style.RESET}")
    print(f"   {Style.BOLD}6{Style.RESET}) Create new file in monitored directory           {Style.YELLOW}[MEDIUM]{Style.RESET}")
    print(f"   {Style.BOLD}7{Style.RESET}) Modify monitored file (tamper SHA-256 hash)     {Style.RED}[HIGH]{Style.RESET}")
    print(f"   {Style.BOLD}8{Style.RESET}) Delete monitored file                           {Style.RED}[HIGH]{Style.RESET}")

    print(f"\n  {Style.BOLD}{Style.BLUE}SSH AUTHENTICATION & BRUTE FORCE:{Style.RESET}")
    print(f"   {Style.BOLD}9{Style.RESET}) Single failed password attempt                   {Style.YELLOW}[MEDIUM]{Style.RESET}")
    print(f"  {Style.BOLD}10{Style.RESET}) Invalid user login attempt                       {Style.YELLOW}[MEDIUM]{Style.RESET}")
    print(f"  {Style.BOLD}11{Style.RESET}) Successful login                                 {Style.CYAN}[LOW]{Style.RESET}")
    print(f"  {Style.BOLD}12{Style.RESET}) Rapid brute-force attack burst (6 attempts)     {Style.RED}[HIGH]{Style.RESET}")

    print(f"\n  {Style.BOLD}{Style.MAGENTA}CONTROL & CLEANUP:{Style.RESET}")
    print(f"   {Style.BOLD}0{Style.RESET}) Stop / Kill currently active event (Reset to idle)")
    print(f"   {Style.BOLD}q{Style.RESET}) Exit (kills all active events and cleans up)")
    print(f"{Style.CYAN}─{Style.RESET}" * 80)

def main():
    manager = ScenarioManager()

    def cleanup_handler(*args):
        print(f"\n{Style.YELLOW}Exiting and cleaning up all simulator resources...{Style.RESET}")
        manager.stop_current()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)
    atexit.register(manager.stop_current)

    scenario_map = {
        "1": manager.run_scenario_1_tmp_process,
        "2": manager.run_scenario_2_shm_process,
        "3": manager.run_scenario_3_deleted_exe,
        "4": manager.run_scenario_4_new_listen_port,
        "5": manager.run_scenario_5_suspicious_outbound,
        "6": manager.run_scenario_6_fim_create,
        "7": manager.run_scenario_7_fim_modify,
        "8": manager.run_scenario_8_fim_delete,
        "9": manager.run_scenario_9_ssh_fail,
        "10": manager.run_scenario_10_ssh_invalid,
        "11": manager.run_scenario_11_ssh_success,
        "12": manager.run_scenario_12_ssh_brute_force,
        "0": manager.stop_current,
    }

    while True:
        print_banner(manager)
        print_menu()
        try:
            choice = input(f"{Style.BOLD}Select event to run [0-12, q]: {Style.RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            cleanup_handler()

        if choice in ["q", "quit", "exit"]:
            cleanup_handler()
        elif choice in scenario_map:
            scenario_map[choice]()
            input(f"\n{Style.DIM}Press [Enter] to return to menu or switch event...{Style.RESET}")
        else:
            print(f"{Style.RED}Invalid selection '{choice}'. Please choose 0-12 or q.{Style.RESET}")
            time.sleep(1.0)

if __name__ == "__main__":
    main()
