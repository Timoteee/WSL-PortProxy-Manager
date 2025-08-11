# WSL-PortProxy-Manager

**Author:** [TimoTeee](https://github.com/Timoteee)  
**License:** © 2025 TimoTeee. All rights reserved.

---

## 📌 About

When running services inside **WSL (Windows Subsystem for Linux)**, accessing them from outside the host machine can be tricky.  
By default, WSL assigns a dynamic IP address on every restart, meaning any static port forwarding rules you set up in Windows using `netsh portproxy` will break after a reboot.

**WSL PortProxy Manager** solves this problem by:
- Automatically detecting the current WSL IP address at startup.
- Allowing you to quickly create, delete, and list Windows `portproxy` rules.
- Giving you a simple GUI instead of typing complex `netsh` commands.
- Ensuring your services (web apps, APIs, SSH, etc.) in WSL are accessible from your Windows host or LAN without manual IP checks.

---

## ✨ Features

- 🖥 **Automatic WSL IP Detection** — Finds your WSL IP when the program opens.
- ✍ **Manual IP Entry** — Override the detected IP if needed.
- ➕ **Add PortProxy Rules** — Forward Windows ports to your WSL services.
- ❌ **Delete Rules** — Remove unused or broken port mappings.
- 📜 **List All Rules** — View all current portproxy rules in one click.
- 🔒 **Admin Privileges Prompt** — Automatically asks to run as Administrator for changes to work.
- 🖱 **Simple GUI** — Built with Tkinter for ease of use.

---

<img width="996" height="827" alt="NVIDIA_Overlay_rnyjQ2swTw" src="https://github.com/user-attachments/assets/5a0f8a54-dfde-43cd-8139-236a920b28ab" />

<img width="991" height="815" alt="image" src="https://github.com/user-attachments/assets/083d8812-c278-4dff-a08b-b1765fad27ae" />


## 🛠 Installation

1. Install **Python 3.x** on your Windows machine.
2. Ensure Tkinter is installed (comes by default with Python on Windows).
3. Download or clone this repository:
   ```bash
   git clone https://github.com/Timoteee/wsl-portproxy-manager.git
   cd wsl-portproxy-manager
