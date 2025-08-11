# WSL-PortProxy-Manager  
**Author:** TimoTeee  
**License:** © 2025 TimoTeee. All rights reserved.

---

## 📌 About  
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

## ✨ Features  

- 🖥 **Automatic WSL IP Detection** — Finds your WSL IP when the program opens.  
- ✍ **Manual IP Entry** — Override the detected IP if needed.  
- ➕ **Add PortProxy Rules** — Forward Windows ports to your WSL services.  
- ❌ **Delete Rules** — Remove unused or broken port mappings.  
- 📜 **List All Rules** — View all current portproxy rules in one click.  
- 🔒 **Admin Privileges Prompt** — Automatically asks to run as Administrator for changes to work.  
- 🖱 **Simple GUI** — Built with Tkinter for ease of use.  
- 📊 **Diagnostics** — Checks Windows/WSL port status and Docker matches.  
- 🐳 **Docker Integration** — Lists containers and ports; one-click forwarding for single/all ports.

---

## 🛠 Installation  

1. Install **Python 3.x** on your Windows machine.  
2. Ensure **Tkinter** is installed (comes by default with Python on Windows).  
3. Download or clone this repository:

```bash
git clone https://github.com/Timoteee/wsl-portproxy-manager.git  
cd wsl-portproxy-manager
