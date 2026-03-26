# MiniEDR User & Agent Help Guide

This guide provides detailed instructions on how to manage the MiniEDR environment, including the Dashboard and Endpoint Agents.

## 🛠️ Server Setup

### 1. Prerequisites
- Python 3.10+
- Internet access (for installing dependencies)

### 2. Installation Steps
```bash
# Clone the repository
git clone https://github.com/shijindas2026/miniedr.git
cd miniedr/edr_server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r ../requirements.txt

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start the server
python manage.py runserver 0.0.0.0:8000
```

## 🖥️ Dashboard Navigation

- **Dashboard**: View high-level metrics for alerts and machine health.
- **Alerts**: Real-time log of security events. Click an alert to see process details and run response tasks.
- **Machines**: Inventory of all connected agents. Perform actions like "Kill Process", "Isolate Machine", or "Run Script" from asset pages.
- **Rules**: Define detection triggers for processes (e.g., `mimikatz.exe`), CPU spikes, or network destinations.

## 🛡️ Agent Deployment (Windows)

### **Build standalone binary** (Optional/One-time)

> [!NOTE]
> Building the standalone binary is typically a **one-time process**. You can use the already available `miniedr-agent.exe` from the `/agent/exe/` directory for deployment across all your Windows machines. 
> 
> **Rebuild only if**:
> - The pre-built executable is not working on a specific OS version.
> - You have modified the agent's source code and need to apply those changes.

1. Copy the project to your target Windows build machine.
2. Build the executable:
   ```cmd
   cd agent
   # Install dependencies
   pip install -r ../requirements.txt pyinstaller
   # Generate standalone .exe
   pyinstaller miniedr-agent.spec
   ```
3. Locate `miniedr-agent.exe` in the `dist/` folder.
4. **Important**: All dependencies like `requests` and `psutil` are bundled into this .exe. No Python installation is needed on the endpoint.

### **Service Installation**
Run these in an **Administrator** command prompt:
- **Install**: `miniedr-agent.exe install --startup auto`
- **Start**: `miniedr-agent.exe start`
- **Stop**: `miniedr-agent.exe stop`
- **Remove**: `miniedr-agent.exe remove`

### **Configuration**
Config is stored at `%PROGRAMDATA%\miniedr\config.json`.
Example:
```json
{
  "server": "http://192.168.1.100:8000"
}
```

## 🐧 Agent Deployment (Linux)
The Linux agent can be installed as a systemd service.

1. **Install**:
   ```bash
   sudo ./agent/install_linux.sh
   # Enter server URL when prompted
   ```
2. **Config Location**: `/var/lib/miniedr/config.json`
3. **Service Management**:
   ```bash
   sudo systemctl status miniedr-agent
   sudo systemctl restart miniedr-agent
   ```

## 📋 Response Tasks
The agent supports the following remote actions triggered from the dashboard:
- **Kill Process**: Stops a running process via its PID.
- **Isolate Network**: Blocks all outbound network traffic except to the EDR Server.
- **Rejoin Network**: Restores network connectivity.
- **Run Script**: Executes arbitrary shell/powershell commands on the endpoint.
