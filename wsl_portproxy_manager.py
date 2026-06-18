"""
WSL PortProxy Manager
Author: TimoTeee
GitHub: https://github.com/Timoteee
Copyright (c) 2025 TimoTeee
All rights reserved.

This script:
 - Parses `netsh interface portproxy show all` to list Windows portproxy rules
 - Tests whether the listen ports are reachable from Windows (WIN OPEN/CLOSED)
 - Queries WSL to see which ports are listening inside the WSL distro (WSL RUNNING/NOT RUNNING)
 - If Docker is present inside WSL, lists running containers and their published ports (DOCKER PORT)
 - Shows combined colour-coded status in a Tkinter GUI
 - Automatic WSL IP detection
 - Manual IP entry
 - Add/Delete portproxy rules
 - Vertical tab for Docker containers to select and open ports
"""

import subprocess
import socket
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import sys
import ctypes
import time
import threading
import re

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROGRAM_NAME = "WSL PortProxy Manager"
PROGRAM_AUTHOR = "TimoTeee"
PROGRAM_GITHUB = "https://github.com/Timoteee"
PROGRAM_COPYRIGHT = f"\u00a9 2025 {PROGRAM_AUTHOR} - {PROGRAM_GITHUB}"

DEFAULT_GEOMETRY = "1000x800"
MIN_WINDOW_WIDTH = 800
MIN_WINDOW_HEIGHT = 600
AUTO_REFRESH_INTERVAL_MS = 30000
SOCKET_CHECK_TIMEOUT = 1
NETSH_TIMEOUT = 5
WSL_CMD_TIMEOUT = 5
DOCKER_CMD_TIMEOUT = 6
ADMIN_ELEVATION_DELAY = 2
FALLBACK_LISTEN_ADDR = "0.0.0.0"


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def is_admin():
    """Return True if the process is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_as_admin():
    """Re-launch the current script with Administrator privileges."""
    script = sys.executable
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 1)
        return True
    except Exception as e:
        messagebox.showerror("Elevation Error", f"Failed to elevate privileges: {e}")
        return False


def safe_run(cmd, timeout=6):
    """Run a subprocess and return (stdout, None) on success, (None, error) on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout, None
        else:
            return None, result.stderr
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as e:
        return None, str(e)


def check_win_port(host, port, timeout=SOCKET_CHECK_TIMEOUT):
    """Check from Windows whether host:port accepts TCP connections."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def is_valid_port(port_str):
    """Return True if port_str is an integer in [1, 65535]."""
    try:
        p = int(port_str)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_ipv4(ip_str):
    """Rudimentary IPv4 address validation."""
    if not ip_str or ip_str == "*":
        return True
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            n = int(part)
            if n < 0 or n > 255:
                return False
        except ValueError:
            return False
    return True


def sanitize_netsh_arg(value):
    """
    Strip characters that could break the netsh command line.
    netsh does not support quotes, semicolons, or newlines in arguments.
    """
    return re.sub(r'[;&|<>"\'`\n\r]', "", value.strip())


# ---------------------------------------------------------------------------
# WSL / Docker detection
# ---------------------------------------------------------------------------

def get_wsl_ip():
    """Detect the WSL instance IP address via multiple methods."""
    methods = [
        ["wsl", "bash", "-c", r"ip addr show eth0 | grep -oP '(?<=inet\s)\d+(?:\.\d+){3}'"],
        ["wsl", "bash", "-c", "hostname -I"],
        ["wsl", "bash", "-c", r"ip route get 1 | awk '{print $NF; exit}'"],
    ]
    errors = []
    for cmd in methods:
        out, err = safe_run(cmd, timeout=WSL_CMD_TIMEOUT)
        if out:
            ip = out.strip().split()[0] if out.strip() else None
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip, None
        errors.append(f"{' '.join(cmd)}: {err or 'no output'}")
    return None, errors


def get_docker_ps_output():
    """Attempt to get docker ps output via multiple methods.

    Returns (output_string, debug_messages_list).
    """
    debug_msgs = []

    # Try Docker Desktop (Windows native)
    docker_check, docker_err = safe_run(
        ["docker", "--version"], timeout=DOCKER_CMD_TIMEOUT
    )
    if docker_check:
        debug_msgs.append(f"Docker Desktop version: {docker_check.strip()}")
        docker_out, docker_err = safe_run(
            ["docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Ports}}"],
            timeout=DOCKER_CMD_TIMEOUT,
        )
        if docker_out:
            debug_msgs.append("Docker Desktop detected.")
            return docker_out, debug_msgs
        debug_msgs.append(f"Docker Desktop ps failed: {docker_err or 'unknown'}")
    else:
        debug_msgs.append(f"Docker Desktop not detected: {docker_err or 'unknown'}")

    # Try WSL Docker (default user)
    wsl_check, wsl_err = safe_run(
        ["wsl", "docker", "--version"], timeout=DOCKER_CMD_TIMEOUT
    )
    if wsl_check:
        debug_msgs.append(f"WSL Docker version: {wsl_check.strip()}")
        docker_out, docker_err = safe_run(
            ["wsl", "docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Ports}}"],
            timeout=DOCKER_CMD_TIMEOUT,
        )
        if docker_out:
            debug_msgs.append("WSL Docker detected.")
            return docker_out, debug_msgs
        debug_msgs.append(f"WSL Docker ps failed: {docker_err or 'unknown'}")
    else:
        debug_msgs.append(f"WSL Docker not detected: {wsl_err or 'unknown'}")

    # Try WSL Docker as root
    wsl_root_check, wsl_root_err = safe_run(
        ["wsl", "-u", "root", "docker", "--version"], timeout=DOCKER_CMD_TIMEOUT
    )
    if wsl_root_check:
        debug_msgs.append(f"WSL root Docker version: {wsl_root_check.strip()}")
        docker_out, docker_err = safe_run(
            ["wsl", "-u", "root", "docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Ports}}"],
            timeout=DOCKER_CMD_TIMEOUT,
        )
        if docker_out:
            debug_msgs.append("WSL root Docker detected.")
            return docker_out, debug_msgs
        debug_msgs.append(f"WSL root Docker ps failed: {docker_err or 'unknown'}")
    else:
        debug_msgs.append(f"WSL root Docker not detected: {wsl_root_err or 'unknown'}")

    return None, debug_msgs


# ---------------------------------------------------------------------------
# Parsing functions
# ---------------------------------------------------------------------------

def parse_netsh_portproxy(raw):
    """
    Parse the output of ``netsh interface portproxy show all``.

    Returns a list of dicts with keys:
        listen_addr, listen_port, connect_addr, connect_port.
    """
    if not raw:
        return []

    lines = raw.splitlines()
    rules = []
    dash_idx = None

    for i, line in enumerate(lines):
        if re.match(r"^-{3,}\s+-{3,}", line.strip()):
            dash_idx = i
            break
    if dash_idx is None:
        for i, line in enumerate(lines):
            if line.strip().lower().startswith("address"):
                dash_idx = i + 1
                break

    start = dash_idx + 1 if dash_idx is not None else 0
    for line in lines[start:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            rules.append({
                "listen_addr": parts[0],
                "listen_port": parts[1],
                "connect_addr": parts[2],
                "connect_port": parts[3],
            })
    return rules


def parse_wsl_listening(ss_output):
    """
    Parse ``ss`` or ``netstat`` output for listening TCP ports inside WSL.

    Returns a set of integer port numbers.
    """
    ports = set()
    if not ss_output:
        return ports
    for line in ss_output.splitlines():
        m = re.search(r"LISTEN.*?(\d{1,3}(?:\.\d+){3}):(\d+)", line)
        if not m:
            m = re.search(r"LISTEN.*?([\[\]:\w\.]+):(\d+)", line)
        if m:
            port = int(m.group(2))
            ports.add(port)
        else:
            m2 = re.search(r":(\d+)\s*$", line.strip())
            if m2:
                ports.add(int(m2.group(1)))
    return ports


def parse_docker_ps_ports(docker_ps_output):
    """
    Parse ``docker ps --format "{{.ID}} {{.Names}} {{.Ports}}"`` output.

    Returns a list of dicts: {id, name, ports_list}.
    Each port entry is a tuple (host_ip, host_port, container_port, protocol).
    """
    containers = []
    if not docker_ps_output:
        return containers
    for line in docker_ps_output.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) < 2:
            continue
        cid = parts[0]
        name = parts[1]
        ports_field = parts[2] if len(parts) >= 3 else ""
        ports = []
        for p in re.split(r",\s*", ports_field):
            p = p.strip()
            if not p:
                continue
            m = re.match(
                r"(?P<hip>[\d.]+):(?P<hport>\d+)->(?P<cport>\d+)(?:/(?P<proto>\w+))?",
                p,
            )
            if m:
                ports.append((
                    m.group("hip"),
                    int(m.group("hport")),
                    int(m.group("cport")),
                    m.group("proto") or "tcp",
                ))
                continue
            m2 = re.match(
                r"(?:(?P<h2ip>[\d.]+):)?(?P<h2port>\d+)"
                r"(?:->(?P<c2port>\d+))?(?:/(?P<p2>\w+))?",
                p,
            )
            if m2:
                hip = m2.group("h2ip") or ""
                hport = int(m2.group("h2port"))
                cport = int(m2.group("c2port")) if m2.group("c2port") else None
                proto = m2.group("p2") or "tcp"
                ports.append((hip, hport, cport, proto))
        containers.append({
            "id": cid,
            "name": name,
            "ports": ports,
            "raw": ports_field,
        })
    return containers


# ---------------------------------------------------------------------------
# Main diagnostic check
# ---------------------------------------------------------------------------

def perform_diagnostic_check():
    """Run all checks in a background thread.

    Returns a dict with keys:
        rules, wsl_listening, docker_containers, netsh_raw, errors, docker_debug.
    """
    result = {
        "rules": [],
        "wsl_listening": set(),
        "docker_containers": [],
        "netsh_raw": None,
        "errors": [],
        "docker_debug": [],
    }

    # netsh portproxy rules
    netsh_out, netsh_err = safe_run(
        ["netsh", "interface", "portproxy", "show", "all"], timeout=NETSH_TIMEOUT
    )
    result["netsh_raw"] = netsh_out
    if netsh_err:
        result["errors"].append(f"netsh error: {netsh_err}")

    rules = parse_netsh_portproxy(netsh_out)

    # WSL listening ports
    ss_out, ss_err = safe_run(["wsl", "ss", "-tulpn"], timeout=WSL_CMD_TIMEOUT)
    if ss_out is None:
        ss_out, ss_err = safe_run(
            ["wsl", "sudo", "ss", "-tulpn"], timeout=WSL_CMD_TIMEOUT
        )
    if ss_out is None:
        ss_out, ss_err = safe_run(
            ["wsl", "netstat", "-tulpn"], timeout=WSL_CMD_TIMEOUT
        )
    if ss_out is None:
        ss_out, ss_err = safe_run(
            ["wsl", "sudo", "netstat", "-tulpn"], timeout=WSL_CMD_TIMEOUT
        )
    if ss_err and ss_out is None:
        result["errors"].append(f"WSL listening ports error: {ss_err}")
    wsl_ports = parse_wsl_listening(ss_out)
    result["wsl_listening"] = wsl_ports

    # Docker
    docker_out, docker_debug = get_docker_ps_output()
    result["docker_debug"] = docker_debug
    docker_containers = parse_docker_ps_ports(docker_out) if docker_out else []
    result["docker_containers"] = docker_containers

    for r in rules:
        laddr = r["listen_addr"]
        lport = r["listen_port"]
        caddr = r["connect_addr"]
        cport = r["connect_port"]

        rule_entry = {
            "listen_addr": laddr,
            "listen_port": lport,
            "connect_addr": caddr,
            "connect_port": cport,
            "win_open": False,
            "wsl_running": False,
            "docker_matches": [],
        }

        try:
            host_to_check = "127.0.0.1" if laddr in ("0.0.0.0", "*") else laddr
            rule_entry["win_open"] = check_win_port(host_to_check, lport)
        except Exception:
            rule_entry["win_open"] = False

        try:
            rule_entry["wsl_running"] = int(cport) in wsl_ports
        except Exception:
            rule_entry["wsl_running"] = False

        for c in docker_containers:
            for port_map in c["ports"]:
                hip, hport, cport_map, proto = port_map
                if (hport and int(hport) == int(cport)) or \
                   (cport_map and int(cport_map) == int(cport)):
                    rule_entry["docker_matches"].append({
                        "container_id": c["id"],
                        "name": c["name"],
                        "host_ip": hip,
                        "host_port": hport,
                        "container_port": cport_map,
                        "proto": proto,
                    })

        result["rules"].append(rule_entry)

    return result


# ---------------------------------------------------------------------------
# Tkinter GUI
# ---------------------------------------------------------------------------

class App:
    """Main application GUI."""

    def __init__(self, root):
        self.root = root
        self.root.title(f"{PROGRAM_NAME} - by {PROGRAM_AUTHOR}")
        self.root.geometry(DEFAULT_GEOMETRY)
        self.root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)

        # State
        self.docker_data = []
        self._refresh_running = False
        self._auto_timer = None

        try:
            self._build_ui()
            self._bind_shortcuts()

            # Initial detection and refresh
            self.detect_wsl_ip()
            self.refresh()

        except Exception as e:
            messagebox.showerror(
                "Initialization Error", f"Failed to launch GUI: {str(e)}"
            )
            root.destroy()
            sys.exit(1)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        root = self.root

        # -- Top controls ----------------------------------------------------
        ctrl_frame = tk.Frame(root)
        ctrl_frame.pack(padx=8, pady=6, fill="x")

        self.refresh_btn = tk.Button(
            ctrl_frame, text="Refresh", command=self.refresh
        )
        self.refresh_btn.pack(side="left", padx=4)

        self.auto_var = tk.BooleanVar(value=False)
        self.auto_chk = tk.Checkbutton(
            ctrl_frame,
            text="Auto-refresh every 30s",
            variable=self.auto_var,
            command=self.toggle_auto,
        )
        self.auto_chk.pack(side="left", padx=8)

        self.clear_btn = tk.Button(
            ctrl_frame, text="Clear Output", command=self.clear_output
        )
        self.clear_btn.pack(side="left", padx=4)

        # -- WSL IP section --------------------------------------------------
        ip_frame = tk.Frame(root)
        ip_frame.pack(padx=8, pady=6, fill="x")
        tk.Label(ip_frame, text="WSL IP:").pack(side="left")
        self.wsl_ip_var = tk.StringVar()
        self.wsl_ip_entry = tk.Entry(ip_frame, textvariable=self.wsl_ip_var, width=20)
        self.wsl_ip_entry.pack(side="left", padx=4)
        self.detect_btn = tk.Button(
            ip_frame, text="Detect", command=self.detect_wsl_ip
        )
        self.detect_btn.pack(side="left", padx=4)

        # -- Add rule section ------------------------------------------------
        add_frame = tk.Frame(root)
        add_frame.pack(padx=8, pady=6, fill="x")
        tk.Label(add_frame, text="Add Rule:").pack(side="left", padx=4)
        tk.Label(add_frame, text="Listen Addr:").pack(side="left")

        self.la_var = tk.StringVar(value=FALLBACK_LISTEN_ADDR)
        self.la_entry = tk.Entry(add_frame, textvariable=self.la_var, width=15)
        self.la_entry.pack(side="left", padx=2)

        tk.Label(add_frame, text="Listen Port:").pack(side="left")
        self.lp_var = tk.StringVar()
        self.lp_entry = tk.Entry(add_frame, textvariable=self.lp_var, width=6)
        self.lp_entry.pack(side="left", padx=2)

        tk.Label(add_frame, text="Connect Addr:").pack(side="left")
        self.ca_var = tk.StringVar()
        self.ca_entry = tk.Entry(add_frame, textvariable=self.ca_var, width=15)
        self.ca_entry.pack(side="left", padx=2)

        tk.Label(add_frame, text="Connect Port:").pack(side="left")
        self.cp_var = tk.StringVar()
        self.cp_entry = tk.Entry(add_frame, textvariable=self.cp_var, width=6)
        self.cp_entry.pack(side="left", padx=2)

        self.add_btn = tk.Button(add_frame, text="Add", command=self.add_rule)
        self.add_btn.pack(side="left", padx=4)

        # Bind Enter key to add_rule on all input fields
        for entry in (self.la_entry, self.lp_entry, self.ca_entry, self.cp_entry):
            entry.bind("<Return>", lambda _: self.add_rule())

        # -- Rules treeview --------------------------------------------------
        rules_frame = tk.Frame(root)
        rules_frame.pack(padx=8, pady=6, fill="both", expand=True)

        columns = (
            "listen_addr", "listen_port", "connect_addr", "connect_port", "status"
        )
        self.rules_tree = ttk.Treeview(
            rules_frame, columns=columns, show="headings", selectmode="extended",
        )
        self.rules_tree.heading("listen_addr", text="Listen Addr")
        self.rules_tree.heading("listen_port", text="Listen Port")
        self.rules_tree.heading("connect_addr", text="Connect Addr")
        self.rules_tree.heading("connect_port", text="Connect Port")
        self.rules_tree.heading("status", text="Status")
        self.rules_tree.column("listen_addr", width=150)
        self.rules_tree.column("listen_port", width=100)
        self.rules_tree.column("connect_addr", width=150)
        self.rules_tree.column("connect_port", width=100)
        self.rules_tree.column("status", width=400)
        self.rules_tree.pack(side="left", fill="both", expand=True)

        self.rules_tree.bind("<Button-3>", self._on_rules_right_click)
        self.rules_tree.bind("<Delete>", lambda _: self.delete_rules())

        scrollbar = ttk.Scrollbar(
            rules_frame, orient="vertical", command=self.rules_tree.yview
        )
        self.rules_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        # -- Delete button ---------------------------------------------------
        delete_btn = tk.Button(root, text="Delete Selected", command=self.delete_rules)
        delete_btn.pack(pady=4)

        # -- Output notebook -------------------------------------------------
        self.output_notebook = ttk.Notebook(root)
        self.output_notebook.pack(padx=8, pady=6, fill="both", expand=True)

        # Diagnostics tab
        diag_frame = tk.Frame(self.output_notebook)
        self.output_text = scrolledtext.ScrolledText(
            diag_frame, width=100, height=15, state="normal", wrap="none"
        )
        self.output_text.pack(fill="both", expand=True)
        self.output_notebook.add(diag_frame, text="Diagnostics")

        # Docker Ports tab
        docker_frame = tk.Frame(self.output_notebook)
        self.output_notebook.add(docker_frame, text="Docker Ports")

        self.docker_container_tree = ttk.Treeview(
            docker_frame, columns=("name",), show="headings", selectmode="browse"
        )
        self.docker_container_tree.heading("name", text="Container Name")
        self.docker_container_tree.pack(side="left", fill="y")

        docker_scroll = ttk.Scrollbar(
            docker_frame, orient="vertical", command=self.docker_container_tree.yview
        )
        self.docker_container_tree.configure(yscroll=docker_scroll.set)
        docker_scroll.pack(side="left", fill="y")

        self.docker_port_frame = tk.Frame(docker_frame)
        self.docker_port_frame.pack(side="right", fill="both", expand=True)
        self.docker_port_tree = ttk.Treeview(
            self.docker_port_frame,
            columns=("host_port", "container_port", "proto"),
            show="headings",
        )
        self.docker_port_tree.heading("host_port", text="Host Port")
        self.docker_port_tree.heading("container_port", text="Container Port")
        self.docker_port_tree.heading("proto", text="Protocol")
        self.docker_port_tree.pack(fill="both", expand=True)

        self.docker_container_tree.bind(
            "<<TreeviewSelect>>", self.on_container_select
        )
        tk.Button(
            self.docker_port_frame, text="Open All Ports", command=self.open_all_ports
        ).pack(pady=5)

        # -- Text tags -------------------------------------------------------
        self.output_text.tag_config(
            "default", foreground="black", font=("Courier", 10)
        )
        self.output_text.tag_config(
            "error", foreground="red", font=("Courier", 10)
        )

        # -- Status bar ------------------------------------------------------
        self.status_var = tk.StringVar(value="Ready.")
        status_label = tk.Label(
            root, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w"
        )
        status_label.pack(fill="x", side="bottom")

        # -- About label -----------------------------------------------------
        about_label = tk.Label(
            root,
            text=f"{PROGRAM_COPYRIGHT}  |  {PROGRAM_GITHUB}",
            font=("Arial", 8),
            fg="gray",
        )
        about_label.pack(side="bottom", pady=3)

        # -- Context menu for rules tree -------------------------------------
        self._rule_menu = tk.Menu(root, tearoff=0)
        self._rule_menu.add_command(label="Delete", command=self.delete_rules)
        self._rule_menu.add_separator()
        self._rule_menu.add_command(label="Refresh", command=self.refresh)

    def _bind_shortcuts(self):
        """Register global keyboard shortcuts."""
        self.root.bind("<Control-r>", lambda _: self.refresh())
        self.root.bind("<Control-R>", lambda _: self.refresh())

    def _on_rules_right_click(self, event):
        """Show context menu on right-click in the rules tree."""
        item = self.rules_tree.identify_row(event.y)
        if item:
            self.rules_tree.selection_set(item)
        self._rule_menu.tk_popup(event.x_root, event.y_root)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def detect_wsl_ip(self):
        """Detect WSL IP and auto-fill the connect address field."""
        ip, err = get_wsl_ip()
        if ip:
            self.wsl_ip_var.set(ip)
            self.ca_var.set(ip)
        else:
            err_msg = (
                err
                if isinstance(err, str)
                else ("; ".join(err) if err else "Unknown error")
            )
            messagebox.showerror("Error", f"Could not detect WSL IP:\n{err_msg}")
            self.ca_var.set("")

    def add_rule(self):
        """Add a portproxy rule with input validation."""
        la = sanitize_netsh_arg(self.la_var.get().strip())
        lp = self.lp_var.get().strip()
        ca = sanitize_netsh_arg(self.ca_var.get().strip())
        cp = self.cp_var.get().strip()

        if not la or not lp or not ca or not cp:
            messagebox.showerror("Error", "All fields are required.")
            return

        if not is_valid_port(lp):
            messagebox.showerror(
                "Error", f"Invalid listen port: {lp} (must be 1-65535)"
            )
            return

        if not is_valid_port(cp):
            messagebox.showerror(
                "Error", f"Invalid connect port: {cp} (must be 1-65535)"
            )
            return

        if not is_valid_ipv4(la):
            messagebox.showerror("Error", f"Invalid listen address: {la}")
            return

        if not is_valid_ipv4(ca):
            messagebox.showerror("Error", f"Invalid connect address: {ca}")
            return

        if la == ca and lp == cp:
            if not messagebox.askyesno(
                "Confirm",
                f"Listen and connect address/port are the same "
                f"({la}:{lp}).\nThis creates a loopback rule. Continue?",
            ):
                return

        cmd = [
            "netsh",
            "interface",
            "portproxy",
            "add",
            "v4tov4",
            f"listenaddress={la}",
            f"listenport={lp}",
            f"connectaddress={ca}",
            f"connectport={cp}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo(
                    "Success", f"Rule added: {la}:{lp} -> {ca}:{cp}"
                )
                self.lp_var.set("")
                self.cp_var.set("")
                self.la_var.set(FALLBACK_LISTEN_ADDR)
                self.ca_var.set(self.wsl_ip_var.get())
                self.refresh()
            else:
                messagebox.showerror("Error", result.stderr)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_rules(self):
        """Delete selected portproxy rules."""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning(
                "No Selection", "Select one or more rules to delete."
            )
            return
        if not messagebox.askyesno(
            "Confirm", f"Delete {len(selected)} selected rule(s)?"
        ):
            return
        for item in selected:
            values = self.rules_tree.item(item)["values"]
            la, lp = values[0], values[1]
            la = sanitize_netsh_arg(la)
            lp = sanitize_netsh_arg(lp)
            cmd = [
                "netsh",
                "interface",
                "portproxy",
                "delete",
                "v4tov4",
                f"listenaddress={la}",
                f"listenport={lp}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                messagebox.showerror(
                    "Error", f"Failed to delete {la}:{lp}\n{result.stderr}"
                )
        self.refresh()

    def clear_output(self):
        """Clear the diagnostics output text."""
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")
        self.status_var.set("Output cleared.")

    # ------------------------------------------------------------------
    # Auto-refresh
    # ------------------------------------------------------------------

    def toggle_auto(self):
        """Toggle the auto-refresh timer."""
        if self.auto_var.get():
            self.status_var.set("Auto-refresh enabled (30s).")
            self._schedule_auto()
        else:
            self.status_var.set("Auto-refresh disabled.")
            self._cancel_auto()

    def _schedule_auto(self):
        """Schedule the next auto-refresh if still enabled."""
        self._cancel_auto()
        if self.auto_var.get():
            self._auto_timer = self.root.after(
                AUTO_REFRESH_INTERVAL_MS, self.refresh
            )

    def _cancel_auto(self):
        """Cancel any pending auto-refresh timer."""
        if self._auto_timer is not None:
            self.root.after_cancel(self._auto_timer)
            self._auto_timer = None

    # ------------------------------------------------------------------
    # Refresh / worker
    # ------------------------------------------------------------------

    def refresh(self):
        """Trigger a diagnostic refresh in a background thread."""
        if self._refresh_running:
            self.status_var.set("Refresh already in progress...")
            return
        self._cancel_auto()
        self.refresh_btn.config(state="disabled")
        self.status_var.set("Running diagnostic checks...")
        self._refresh_running = True
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        """Background thread: run diagnostics and schedule UI update."""
        try:
            data = perform_diagnostic_check()
        except Exception as e:
            data = {
                "rules": [],
                "wsl_listening": set(),
                "docker_containers": [],
                "netsh_raw": None,
                "errors": [str(e)],
                "docker_debug": [],
            }
        self.root.after(10, lambda: self._update_ui(data))

    def _update_ui(self, data):
        """Update the GUI with diagnostic results (main thread)."""
        self._refresh_running = False

        # Refresh rules tree
        for i in self.rules_tree.get_children():
            self.rules_tree.delete(i)

        for r in data.get("rules", []):
            status_parts = []
            status_parts.append(
                "WIN OPEN" if r["win_open"] else "WIN CLOSED"
            )
            status_parts.append(
                "WSL RUNNING" if r["wsl_running"] else "WSL NOT"
            )

            docker_str = ""
            if r["docker_matches"]:
                port_desc = ", ".join(
                    f"{dm['name']} {dm['host_port']}->{dm['container_port']}"
                    for dm in r["docker_matches"]
                )
                docker_str = f"DOCKER: {port_desc}"

            stat_str = " | ".join(status_parts)
            if docker_str:
                stat_str += f" | {docker_str}"

            self.rules_tree.insert(
                "",
                "end",
                values=(
                    r["listen_addr"],
                    r["listen_port"],
                    r["connect_addr"],
                    r["connect_port"],
                    stat_str,
                ),
            )

        # Diagnostics text
        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)

        self.output_text.insert(
            tk.END,
            "=== WSL Listening Ports (detected inside WSL) ===\n",
            "default",
        )
        wsl_ports = sorted(data.get("wsl_listening", set()))
        if not wsl_ports:
            self.output_text.insert(
                tk.END,
                "No listening ports detected inside WSL, "
                "or `ss`/`netstat` not available.\n\n",
                "default",
            )
        else:
            self.output_text.insert(
                tk.END, ", ".join(str(p) for p in wsl_ports) + "\n\n", "default"
            )

        if data.get("errors"):
            self.output_text.insert(tk.END, "=== Errors ===\n", "error")
            for err in data["errors"]:
                self.output_text.insert(tk.END, f" - {err}\n", "error")
            self.output_text.insert(tk.END, "\n")

        self.output_text.insert(
            tk.END, "=== Raw netsh portproxy output ===\n", "default"
        )
        raw = data.get("netsh_raw")
        if raw:
            self.output_text.insert(tk.END, raw.strip() + "\n", "default")
        else:
            self.output_text.insert(tk.END, "(no netsh output)\n", "default")

        self.output_text.config(state="disabled")

        # Docker tree
        for i in self.docker_container_tree.get_children():
            self.docker_container_tree.delete(i)

        self.docker_data = data.get("docker_containers", [])
        if self.docker_data:
            for idx, c in enumerate(self.docker_data):
                self.docker_container_tree.insert(
                    "", "end", iid=idx, values=(c["name"],)
                )
        elif data.get("docker_debug"):
            self.output_text.config(state="normal")
            self.output_text.insert(tk.END, "\nDocker Debug Info:\n", "error")
            for msg in data["docker_debug"]:
                self.output_text.insert(tk.END, f" - {msg}\n", "error")
            self.output_text.config(state="disabled")

        # Finalize
        self.refresh_btn.config(state="normal")
        self._schedule_auto()
        rule_count = len(data.get("rules", []))
        self.status_var.set(f"Diagnostic complete. {rule_count} rule(s) found.")

    # ------------------------------------------------------------------
    # Docker port forwarding
    # ------------------------------------------------------------------

    def on_container_select(self, event):
        """Docker container selected -> show its ports."""
        selected = self.docker_container_tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        container = self.docker_data[idx]
        for i in self.docker_port_tree.get_children():
            self.docker_port_tree.delete(i)
        for p in container["ports"]:
            hip, hport, cport, proto = p
            self.docker_port_tree.insert(
                "", "end",
                values=(hport, cport or "-", proto),
                tags=(idx, hport),
            )
        self.docker_port_tree.bind(
            "<<TreeviewSelect>>", self._on_port_select
        )

    def _on_port_select(self, event):
        """Docker port selected -> ask to forward."""
        selected = self.docker_port_tree.selection()
        if not selected:
            return
        item = self.docker_port_tree.item(selected[0])
        hport = item["values"][0]
        if messagebox.askyesno("Open Port", f"Forward port {hport}?"):
            self.forward_port(hport)

    def open_all_ports(self):
        """Forward all ports for the selected Docker container."""
        selected_container = self.docker_container_tree.selection()
        if not selected_container:
            messagebox.showwarning("No Selection", "Select a container first.")
            return
        idx = int(selected_container[0])
        container = self.docker_data[idx]
        if not messagebox.askyesno(
            "Open All Ports", f"Forward all ports for {container['name']}?"
        ):
            return
        for p in container["ports"]:
            _, hport, _, _ = p
            self.forward_port(hport)
        self.refresh()

    def forward_port(self, hport):
        """Create a portproxy rule forwarding a single port to WSL."""
        wsl_ip = self.wsl_ip_var.get()
        if not wsl_ip:
            messagebox.showerror(
                "Error", "WSL IP not detected. Click 'Detect' first."
            )
            return

        la = FALLBACK_LISTEN_ADDR
        lp = str(hport)
        ca = wsl_ip
        cp = str(hport)

        cmd = [
            "netsh",
            "interface",
            "portproxy",
            "add",
            "v4tov4",
            f"listenaddress={la}",
            f"listenport={lp}",
            f"connectaddress={ca}",
            f"connectport={cp}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo(
                    "Success", f"Port {hport} forwarded to {wsl_ip}."
                )
            else:
                messagebox.showerror("Error", result.stderr)
        except Exception as e:
            messagebox.showerror("Error", str(e))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Application entry point."""
    try:
        if not is_admin():
            root_tmp = tk.Tk()
            root_tmp.withdraw()
            answer = messagebox.askyesno(
                "Admin Required",
                f"{PROGRAM_NAME} requires Administrator privileges to modify "
                "portproxy rules.\n\nRestart as Administrator?",
            )
            root_tmp.destroy()
            if answer:
                if run_as_admin():
                    time.sleep(ADMIN_ELEVATION_DELAY)
                    sys.exit(0)
                else:
                    messagebox.showerror(
                        "Error",
                        "Could not restart with Administrator privileges.",
                    )
                    sys.exit(1)

        root = tk.Tk()
        App(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror(
            "Startup Error", f"Failed to start program: {str(e)}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
