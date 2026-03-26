"""
Core Monitoring Logic and Task Execution for MiniEDR.
Handles real-time process scanning, system telemetry (heartbeats),
and active response tasks (kill, isolate, execute).
"""
import psutil
import requests
import socket
import json
import os
from rule_engine import load_rules

# Determine if we have access to the Windows Service Manager logging.
try:
    import servicemanager
except ImportError:
    # Fallback logger for non-Windows platforms or development environments.
    class MockServiceManager:
        def LogInfoMsg(self, msg): print(f"INFO: {msg}")
        def LogErrorMsg(self, msg): print(f"ERROR: {msg}")
    servicemanager = MockServiceManager()

from paths import get_config_path, get_rule_path

# Absolute paths to configuration and detection rules.
CONFIG_FILE = get_config_path()
RULE_FILE = get_rule_path()

# Global set to track already reported alerts to prevent alert fatigue (duplicate flooding).
reported = set()

# Global variable storing the EDR Server URL (e.g., http://10.0.0.5:8000).
SERVER = None



def load_config():
    """Reads the server URL from the local config.json file."""
    global SERVER
    try:
        if not os.path.exists(CONFIG_FILE):
            return
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            SERVER = config.get("server")
            # Ensure no trailing slash to prevent double-slashes in API URLs.
            if SERVER and SERVER.endswith("/"):
                SERVER = SERVER.rstrip("/")
    except Exception:
        SERVER = None


def fetch_rules():
    """Downloads updated detection rules from the EDR server and saves them locally."""
    global SERVER
    try:
        # Ensure server URL is known before fetching.
        if not SERVER:
            load_config()
        
        if not SERVER:
            return

        servicemanager.LogInfoMsg("MiniEDR: Initiating rule synchronization...")
        url = SERVER + "/api/rules/"
        response = requests.get(url, timeout=10)

        # Update local storage if the fetch is successful.
        if response.status_code == 200:
            rules_data = response.json()
            with open(RULE_FILE, "w") as f:
                json.dump(rules_data, f, indent=4)
            servicemanager.LogInfoMsg("MiniEDR: Rules synchronized successfully.")
        else:
            servicemanager.LogErrorMsg(f"MiniEDR: Server sync failed with status {response.status_code}")
    except Exception as e:
        servicemanager.LogErrorMsg(f"MiniEDR ERROR: Failed to fetch rules: {str(e)}")


def cleanup_reported():
    """Removes PIDs from the 'reported' set if the processes are no longer active."""
    global reported

    try:
        # Get set of all currently running PIDs.
        active_pids = {p.pid for p in psutil.process_iter(['pid'])}
        # Retain only entries whose PIDs are still in the active set.
        reported = {key for key in reported if key[0] in active_pids}
    except Exception:
        pass


def get_ip_address():
    """Heuristic logic to find the local IP address of the machine."""
    try:
        # Create a dummy socket to see which interface is used to reach the internet.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Google DNS (Connection isn't actually established)
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        # Fallback to local hostname resolution if no internet access is available.
        return socket.gethostbyname(socket.gethostname())


def send_heartbeat():
    """Sends a health check ping to the server and retrieves pending response tasks."""
    if not SERVER:
        return

    url = SERVER + "/api/heartbeat/"
    hostname = socket.gethostname()
    ip = get_ip_address()

    data = {
        "hostname": hostname,
        "ip_address": ip
    }

    try:
        # POST request to report presence.
        response = requests.post(url, json=data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            # If the server has orders (tasks) for this machine, process them.
            pending_tasks = result.get("pending_tasks", [])
            if pending_tasks:
                process_tasks(pending_tasks)
        servicemanager.LogInfoMsg(f"MiniEDR: Heartbeat synchronized.")
    except Exception as e:
        servicemanager.LogErrorMsg(f"MiniEDR: Heartbeat failure: {str(e)}")

def process_tasks(tasks):
    """Executes specific response commands ordered by the EDR administrator."""
    for task in tasks:
        task_id = task.get("id")
        task_type = task.get("type")
        params = task.get("parameters", {})

        servicemanager.LogInfoMsg(f"MiniEDR: Executing Active Response task: {task_type} (ID: {task_id})")

        result_data = {"status": "completed", "result": ""}

        try:
            # 1. KILL PROCESS: Forcefully terminates a running process by its PID.
            if task_type == "kill_process":
                pid = params.get("pid")
                if pid:
                    p = psutil.Process(pid)
                    p.kill()
                    result_data["result"] = f"Success: Process {pid} terminated."
                else:
                    result_data["status"] = "failed"
                    result_data["result"] = "Error: PID parameter missing."
            
            # 2. ISOLATE NETWORK: Blocks all outbound traffic EXCEPT to the EDR Server.
            elif task_type == "isolate_network":
                import subprocess
                import platform
                
                server_host = "localhost" 
                if SERVER:
                    # Extract raw hostname/IP from the SERVER URL for firewall filtering.
                    server_host = SERVER.split("//")[-1].split(":")[0]
                
                try:
                    # Windows Logic: Uses PowerShell NetFirewall commands.
                    if platform.system() == "Windows":
                        # Clear old rules, then create a whitelist for the EDR server and block everything else.
                        subprocess.run(["powershell", "-Command", "Get-NetFirewallRule -Description 'MiniEDR_Isolation' | Remove-NetFirewallRule -ErrorAction SilentlyContinue"], check=True)
                        subprocess.run(["powershell", "-Command", f"New-NetFirewallRule -Name 'MiniEDR_Allow_Server' -DisplayName 'MiniEDR Allow EDR Server' -Direction Outbound -Action Allow -RemoteAddress '{server_host}' -Description 'MiniEDR_Isolation'"], check=True)
                        subprocess.run(["powershell", "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block"], check=True)
                        result_data["result"] = f"Windows machine isolated. Whitelisted EDR Server: {server_host}."
                    
                    # Linux Logic: Uses iptables for outbound DROP rules.
                    else:
                        # Create a dedicated 'MINIEDR_ISO' chain for easier tracking and removal.
                        subprocess.run(["iptables", "-N", "MINIEDR_ISO"], capture_output=True)
                        subprocess.run(["iptables", "-F", "MINIEDR_ISO"], check=True)
                        
                        # Rule A: Allow traffic to the EDR server.
                        subprocess.run(["iptables", "-A", "MINIEDR_ISO", "-d", server_host, "-j", "ACCEPT"], check=True)
                        # Rule B: Drop all other traffic.
                        subprocess.run(["iptables", "-A", "MINIEDR_ISO", "-j", "DROP"], check=True)
                        
                        # Insert the jump command at index 1 of the standard OUTPUT chain.
                        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "MINIEDR_ISO"], capture_output=True) 
                        subprocess.run(["iptables", "-I", "OUTPUT", "1", "-j", "MINIEDR_ISO"], check=True)
                        
                        result_data["result"] = f"Linux machine isolated via iptables. Whitelisted EDR Server: {server_host}."
                except Exception as firewall_err:
                    result_data["status"] = "failed"
                    result_data["result"] = f"Firewall command failed: {str(firewall_err)}. Ensure script runs with sudo/Admin."

            # 3. REJOIN NETWORK: Restoration of normal network communications.
            elif task_type == "rejoin_network":
                import subprocess
                import platform
                try:
                    if platform.system() == "Windows":
                        # Set default outbound back to Allow and remove blocking rules.
                        subprocess.run(["powershell", "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow"], check=True)
                        subprocess.run(["powershell", "-Command", "Get-NetFirewallRule -Description 'MiniEDR_Isolation' | Remove-NetFirewallRule -ErrorAction SilentlyContinue"], check=True)
                        result_data["result"] = "Windows machine network restored."
                    else:
                        # Flush and delete the custom iptables chain.
                        subprocess.run(["iptables", "-D", "OUTPUT", "-j", "MINIEDR_ISO"], capture_output=True)
                        subprocess.run(["iptables", "-F", "MINIEDR_ISO"], check=True)
                        subprocess.run(["iptables", "-X", "MINIEDR_ISO"], check=True)
                        result_data["result"] = "Linux machine network restored (iptables cleared)."
                except Exception as e:
                    result_data["status"] = "failed"
                    result_data["result"] = f"Rejoin failed: {str(e)}"

            # 4. EXECUTE SCRIPT: Runs arbitrary shell/powershell commands on the endpoint.
            elif task_type == "execute_script":
                import subprocess
                import platform
                script_content = params.get("script")
                if script_content:
                    # Choose shell depending on host OS.
                    if platform.system() == "Windows":
                        process = subprocess.Popen(["powershell", "-Command", script_content], 
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    else:
                        process = subprocess.Popen(["/bin/sh", "-c", script_content], 
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    
                    stdout, stderr = process.communicate()
                    result_data["result"] = f"Script execution finished.\nSTDOUT: {stdout}\nSTDERR: {stderr}"
                else:
                    result_data["status"] = "failed"
                    result_data["result"] = "No script content provided for execution."

            else:
                result_data["status"] = "failed"
                result_data["result"] = f"Error: Unsupported task type '{task_type}'."

        # Handle OS/Privilege level errors specifically.
        except psutil.AccessDenied:
            result_data["status"] = "failed"
            result_data["result"] = "Access Denied: Agent lacks sufficient privileges for this operation."
        except psutil.NoSuchProcess:
            result_data["status"] = "failed"
            result_data["result"] = "Error: Targeted process is no longer running."
        except Exception as e:
            result_data["status"] = "failed"
            result_data["result"] = f"Execution error: {str(e)}"

        # Report the outcome of the task back to the server.
        if SERVER:
            url = f"{SERVER}/api/tasks/{task_id}/result/"
            try:
                requests.post(url, json=result_data, timeout=5)
                servicemanager.LogInfoMsg(f"MiniEDR: Task {task_id} result reported: {result_data['status']}")
            except Exception as e:
                servicemanager.LogErrorMsg(f"MiniEDR: Final task report failed: {str(e)}")


def send_process_inventory():
    """Uploads a complete snapshot of all running processes for central visibility."""
    if not SERVER:
        return

    url = SERVER + "/api/inventory/update/"
    hostname = socket.gethostname()

    processes = []
    # Collect telemetry for every process.
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "username": proc.info['username'],
                "cpu_percent": proc.info['cpu_percent'],
                "memory_percent": proc.info['memory_percent']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Ignore processes that finished during enumeration or offer no access.
            pass

    data = {
        "hostname": hostname,
        "processes": processes
    }

    try:
        # Send full inventory to the central management server.
        requests.post(url, json=data, timeout=10)
        servicemanager.LogInfoMsg(f"MiniEDR: Inventory batch uploaded ({len(processes)} processes).")
    except Exception as e:
        servicemanager.LogErrorMsg(f"MiniEDR: Inventory upload failed: {str(e)}")

def send_alert(alert_type, severity, description):
    """Signals a security detection event to the EDR server."""

    if not SERVER:
        servicemanager.LogErrorMsg("MiniEDR: Server URL missing, cannot transmit alert.")
        return

    url = SERVER + "/api/alerts/"

    hostname = socket.gethostname()
    ip = get_ip_address()

    # Meta-data for the alert.
    data = {
        "hostname": hostname,
        "ip_address": ip,
        "alert_type": alert_type,
        "severity": severity,
        "description": description
    }

    try:
        # Transmit the detection event.
        requests.post(url, json=data, timeout=5)
        servicemanager.LogInfoMsg(f"MiniEDR ALERT TRANSMITTED - {alert_type}: {description}")

    except Exception as e:
        servicemanager.LogErrorMsg(f"MiniEDR: Alert transmission failure: {str(e)}")



def monitor_processes():
    """Performs the main inspection scan for processes, resources, and connections."""
    
    # 0. Maintenance: Clean up tracking set for processes that have exited.
    cleanup_reported()

    # 1. Rules: Load latest policy from memory/local storage.
    rules = load_rules()

    if not rules:
        servicemanager.LogInfoMsg("MiniEDR: No detection rules found. Monitoring idle.")
        return

    global reported

    # SECTION A: PROCESS NAME SCANNING
    process_rules = rules.get("process", {})

    for process in psutil.process_iter(['pid', 'name'], ad_value=None):
        try:
            pid = process.info['pid']
            pname = process.info['name']

            if not pname: continue
            pname = pname.lower()

            key = (pid, pname)

            # Avoid reporting the same suspicious process multiple times if it's already flagged.
            if key in reported:
                continue

            # Flag if process name matches a prohibited pattern in rules.json.
            if pname in process_rules:
                rule_info = process_rules[pname]
                reported.add(key)

                servicemanager.LogInfoMsg(
                    f"MiniEDR DETECTION: Suspicious process matched rule -> {pname} (PID {pid}, severity={rule_info['severity']})"
                )

                send_alert(
                    alert_type="Suspicious Process",
                    severity=rule_info['severity'],
                    description=f"Process name '{pname}' detected on host. (PID: {pid})"
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # SECTION B: CPU USAGE THRESHOLD MONITORING
    cpu_rules = rules.get("cpu", {})
    if cpu_rules:
        # Non-blocking CPU measurement.
        total_cpu = psutil.cpu_percent(interval=None) 
        
        for threshold_str, rule_info in cpu_rules.items():
            try:
                threshold = float(threshold_str)
                # Check if system-wide CPU exceeds defined limit.
                if total_cpu > threshold:
                    alert_key = f"cpu_{threshold}"

                    if alert_key not in reported:
                        reported.add(alert_key)
                        servicemanager.LogInfoMsg(f"MiniEDR DETECTION: High CPU usage {total_cpu}% (Threshold: {threshold}%)")
                        
                        send_alert(
                            alert_type="Resource Alert",
                            severity=rule_info['severity'],
                            description=f"Total system CPU load at {total_cpu}% exceeds configured limit {threshold}%."
                        )
            except:
                continue

    # SECTION C: NETWORK CONNECTION MONITORING
    network_rules = rules.get("network", {})
    if network_rules:
        try:
            # Inspect currently active network sockets.
            for conn in psutil.net_connections(kind='inet'):
                # We focus on successful outbound/inbound connections.
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    
                    # Flag if host is connecting to an IP identified in rules.json.
                    if remote_ip in network_rules:
                        rule_info = network_rules[remote_ip]
                        
                        alert_key = f"net_{remote_ip}_{conn.pid}"
                        
                        if alert_key not in reported:
                            reported.add(alert_key)
                            
                            pname = "Unknown"
                            try:
                                # Attempt to identify the binary responsible for the connection.
                                pname = psutil.Process(conn.pid).name()
                            except:
                                pass

                            servicemanager.LogInfoMsg(
                                f"MiniEDR DETECTION: Malicious IP Connection -> {remote_ip} via {pname} (PID {conn.pid})"
                            )

                            send_alert(
                                alert_type="Network Alert",
                                severity=rule_info['severity'],
                                description=f"Connection established to blacklisted IP {remote_ip} by process {pname} (PID {conn.pid})."
                            )
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            # Access to network telemetry may require elevated permissions.
            pass

# Initialize configuration on module import.
load_config()