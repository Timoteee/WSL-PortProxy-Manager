# WSL PortProxy Manager

**Author:** TimoTeee  
**License:** Apache 2.0  

---

## About

When running services inside WSL (Windows Subsystem for Linux), accessing them from outside the host machine can be tricky.

By default, WSL assigns a dynamic IP address on every restart, meaning any static port forwarding rules you set up in Windows using `netsh portproxy` will break after a reboot.

**WSL PortProxy Manager** solves this problem by:

- Automatically detecting the current WSL IP address at startup.
- Allowing you to quickly create, delete, and list Windows portproxy rules.
- Giving you a simple GUI instead of typing complex `netsh` commands.
- Ensuring your services (web apps, APIs, SSH, etc.) in WSL are accessible from your Windows host or LAN without manual IP checks.

This tool was born out of frustration as a developer working extensively with WSL and Docker on Windows. Constantly checking WSL IPs, manually crafting `netsh` commands, and debugging broken port forwarding after reboots was tedious. This tool makes port management effortless, saving time and reducing errors in dynamic environments like WSL/Docker setups.

**Command-wise, it wraps `netsh interface portproxy` operations:**

- **Add Rule:** Equivalent to
  `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=80 connectaddress=<WSL_IP> connectport=80`
- **Delete Rule:** Equivalent to
  `netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=80`
- **Show Rules:** Parses `netsh interface portproxy show all` with added diagnostics (e.g., port open checks).
- **Docker Port Forwarding:** Automatically creates rules for selected container ports, forwarding Docker's published ports to Windows via WSL IP.

---

## Features

- **Automatic WSL IP Detection** — Finds your WSL IP when the program opens.
- **Manual IP Entry** — Override the detected IP if needed.
- **Add PortProxy Rules** — Forward Windows ports to your WSL services.
- **Delete Rules** — Remove unused or broken port mappings (single or multi-select).
- **List All Rules** — View all current portproxy rules with colour-coded status diagnostics.
- **Admin Privileges Prompt** — Automatically asks to run as Administrator for changes to work.
- **Simple GUI** — Built with Tkinter for ease of use.
- **Diagnostics** — Checks Windows/WSL port status and Docker matches.
- **Docker Integration** — Lists containers and ports; one-click forwarding for single or all ports.
- **Auto-Refresh** — Optional periodic refresh every 30 seconds.
- **Keyboard Shortcuts** — `Ctrl+R` to refresh, `Delete` to delete selected rules.

---

## Screenshots

![Main window](https://github.com/user-attachments/assets/5a0f8a54-dfde-43cd-8139-236a920b28ab)

![Docker ports tab](https://github.com/user-attachments/assets/083d8812-c278-4dff-a08b-b1765fad27ae)

---

## Installation

### Prerequisites

- **Windows 10/11** with WSL enabled and a Linux distro installed.
- **Python 3.6+** on Windows (Tkinter is included by default).
- Administrator privileges (required for modifying portproxy rules).

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/Timoteee/WSL-PortProxy-Manager.git
   cd WSL-PortProxy-Manager
   ```

2. Run the application:

   ```batch
   python wsl_portproxy_manager.py
   ```

   Or double-click `run.bat` (recommended).

3. When prompted, click **Yes** to grant Administrator privileges (required to add/delete portproxy rules).

---

## Usage

1. **Launch** — The app auto-detects your WSL IP and fetches existing portproxy rules.
2. **Add a rule** — Fill in Listen Address, Listen Port, Connect Address, Connect Port, then click **Add**.
   - Listen Address is pre-filled to `0.0.0.0` (all interfaces).
   - Connect Address auto-fills with your detected WSL IP.
3. **Delete a rule** — Select one or more rules in the table, then click **Delete Selected** (or press `Delete` key).
4. **Refresh** — Click **Refresh** to re-run diagnostics (or press `Ctrl+R`).
5. **Docker ports** — Switch to the "Docker Ports" tab, select a container, then click **Open All Ports** or click an individual port to forward it.
6. **Auto-refresh** — Check "Auto-refresh every 30s" to poll continuously.

### Status Indicators

Each rule shows a combined status column:

- **WIN OPEN** / **WIN CLOSED** — Whether the listen port is accepting connections on Windows.
- **WSL RUNNING** / **WSL NOT** — Whether a service on that port is listening inside WSL.
- **DOCKER: <name> <host_port>-><container_port>** — If a running Docker container matches this rule.

---

## How It Works

The tool uses Windows' built-in `netsh interface portproxy` commands under the hood:

| Action | Command |
|--------|---------|
| List rules | `netsh interface portproxy show all` |
| Add rule | `netsh interface portproxy add v4tov4 listenaddress=X listenport=Y connectaddress=Z connectport=W` |
| Delete rule | `netsh interface portproxy delete v4tov4 listenaddress=X listenport=Y` |

For diagnostics, it also runs:

- `wsl ss -tulpn` (or `netstat`) to check listening ports inside WSL.
- `docker ps` to detect running containers and their published ports.
- TCP socket check from Windows to verify port reachability.

---

## Project Structure

```
WSL-PortProxy-Manager/
├── wsl_portproxy_manager.py   # Main application (single file)
├── run.bat                    # Windows launcher script
├── requirements.txt           # Dependency file (stdlib-only)
├── LICENSE                    # Apache 2.0
├── .gitignore                 # Python project ignores
└── README.md                  # This file
```

---

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`.
3. Commit your changes: `git commit -am 'Add my feature'`.
4. Push to the branch: `git push origin feature/my-feature`.
5. Open a pull request.

---

## License

This project is licensed under the Apache License, Version 2.0. See `LICENSE` for details.
