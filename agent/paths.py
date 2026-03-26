"""
Path management utility for MiniEDR agent.
Handles directory and file path resolution for different operating systems (Windows and Linux).
"""
import os
import platform
import sys

def get_data_dir():
    """
    Returns the directory where data files (rules.json, config.json, logs) should be stored.
    
    Logic:
    - Windows: Uses %PROGRAMDATA% (usually C:\ProgramData\MiniEDR) for system-wide service data.
    - Linux: Uses /var/lib/miniedr for persistent agent data.
    - Fallback: If directories cannot be created (e.g., lack of permissions), 
      falls back to a 'data' folder in the current working directory.
    """
    if platform.system() == "Windows":
        # Use ProgramData for Windows services to ensure they are accessible by the System account
        base = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        path = os.path.join(base, "MiniEDR")
    else:
        # Use /var/lib/miniedr for Linux as it's the standard for persistent application data
        path = "/var/lib/miniedr"
    
    # Attempt to ensure the directory exists
    try:
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
    except Exception:
        # Fallback to current working directory if permission denied (common during development)
        # Note: In a production environment, root/administrator privileges are expected.
        fallback_path = os.path.join(os.getcwd(), "data")
        os.makedirs(fallback_path, exist_ok=True)
        return fallback_path
        
    return path

def get_config_path():
    """Returns the absolute path to the agent configuration file (config.json)."""
    return os.path.join(get_data_dir(), "config.json")

def get_rule_path():
    """Returns the absolute path to the local detection rules file (rules.json)."""
    return os.path.join(get_data_dir(), "rules.json")

