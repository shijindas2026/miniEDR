# MiniEDR (Mini Endpoint Detection and Response)

A streamlined detection and response platform using **Django** and **AdminLTE 4**.

## 🚀 Features
- **Dashboard**: High-level overview of critical alerts and machine statuses.
- **Alert Stream**: Real-time table showing security events from all agents.
- **Asset Management**: Monitor which machines are online, inactive, or offline.
- **Custom Rules**: Create detection rules for specific process names or CPU thresholds.
- **Endpoint Agent**: Lightweight service for Windows and Linux to monitor processes and report alerts.
- **Active Response**: Kill processes, isolate networks, or run scripts remotely from the dashboard.

## 🛠️ Project Structure
- `edr_server/`: The central Django dashboard and API.
- `agent/`: Python scripts and build tools for the endpoint agent.
- `static/`: Frontend assets (AdminLTE 4, Bootstrap 5, Font Awesome 6).

## 📥 Getting Started

For detailed installation instructions, server setup, and agent deployment, please refer to the **[Help Guide](HELP.md)**.

### Quick Start Overview:
1. **Server Setup**: Clone the repository, install dependencies from `requirements.txt`, run Django migrations, and start the server.
2. **Agent Deployment**: Build the standalone binary for Windows or use the install script for Linux, then configure the server URL in `config.json`.

## 🎨 Technology Stack
- **Backend:** Python / Django / Django REST Framework
- **Frontend:** HTML5 / CSS3 / JavaScript
- **Theme:** AdminLTE 4 (Bootstrap 5)
- **Charts:** Chart.js 4
- **Database:** SQLite (default for development)
