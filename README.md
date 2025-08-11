WSL-PortProxy-Manager
Author: TimoTeee

License: © 2025 TimoTeee. All rights reserved.

📌 About
When running services inside WSL (Windows Subsystem for Linux), accessing them from outside the host machine can be tricky.

By default, WSL assigns a dynamic IP address on every restart, meaning any static port forwarding rules you set up in Windows using netsh portproxy will break after a reboot.

WSL PortProxy Manager solves this problem by:

Automatically detecting the current WSL IP address at startup.
Allowing you to quickly create, delete, and list Windows portproxy rules.
Giving you a simple GUI instead of typing complex netsh commands.
Ensuring your services (web apps, APIs, SSH, etc.) in WSL are accessible from your Windows host or LAN without manual IP checks.

This tool was born out of my own frustration as a developer working extensively with WSL and Docker on Windows. I was tired of constantly checking WSL IPs, manually crafting netsh commands, and debugging why ports weren't forwarding correctly after reboots. It makes port management effortless, saving time and reducing errors in dynamic environments like WSL/Docker setups.
Command-wise, it wraps netsh interface portproxy operations:

Add Rule: Equivalent to netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=80 connectaddress=<WSL_IP> connectport=80.
Delete Rule: Equivalent to netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=80.
Show Rules: Parses netsh interface portproxy show all with added diagnostics (e.g., port open checks).
Docker Port Forwarding: Automatically creates rules for selected container ports, e.g., forwarding Docker's published port to Windows via WSL IP.


✨ Features

🖥 Automatic WSL IP Detection — Finds your WSL IP when the program opens.
✍ Manual IP Entry — Override the detected IP if needed.
➕ Add PortProxy Rules — Forward Windows ports to your WSL services.
❌ Delete Rules — Remove unused or broken port mappings.
📜 List All Rules — View all current portproxy rules in one click.
🔒 Admin Privileges Prompt — Automatically asks to run as Administrator for changes to work.
🖱 Simple GUI — Built with Tkinter for ease of use.
📊 Diagnostics — Checks Windows/WSL port status and Docker matches.
🐳 Docker Integration — Lists containers and ports; one-click forwarding for single/all ports.


<img width="996" height="827" alt="NVIDIA_Overlay_rnyjQ2swTw" src="https://github.com/user-attachments/assets/5a0f8a54-dfde-43cd-8139-236a920b28ab">  
<img width="991" height="815" alt="image" src="https://github.com/user-attachments/assets/083d8812-c278-4dff-a08b-b1765fad27ae">
🛠 Installation

Install Python 3.x on your Windows machine.
Ensure Tkinter is installed (comes by default with Python on Windows).
Download or clone this repository:
bashgit clone https://github.com/Timoteee/wsl-portproxy-manager.git  
cd wsl-portproxy-manager

Run the script (as Administrator for full functionality):
bashpython wsl_portproxy_manager.py


🔧 Usage

Launch the app (run as Admin via right-click or prompt).
The WSL IP is auto-detected and filled in "Connect Addr".
Add a Rule: Enter Listen Addr/Port, Connect Port (Connect Addr defaults to WSL IP), click "Add".
View/Delete Rules: Rules appear in the table with status; select and click "Delete Selected".
Diagnostics Tab: Shows WSL listening ports, errors, and raw netsh output.
Docker Ports Tab:

Containers listed on left.
Select one to view ports on right.
Click a port to forward it (creates netsh rule to WSL IP).
"Open All Ports" forwards all for the selected container.


Refresh manually or enable auto-refresh.

🤝 Contributing
Pull requests welcome! For major changes, open an issue first.
📄 License
MIT License. See LICENSE for details.
