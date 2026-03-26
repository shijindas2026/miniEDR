"""
MiniEDR Agent Main Entry Point.
Initializes logging and detects the operating system to start the appropriate service handler.
"""
import platform
import logging
import sys
import os

# Add the current directory to sys.path to allow imports of local agent modules.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Local directory utility to find where to write system and agent logs.
from paths import get_data_dir

# Global logging configuration:
# Logs to both the standard output (STDOUT) and a persistent 'agent.log' file.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(get_data_dir(), "agent.log"))
    ]
)
logger = logging.getLogger("MiniEDR-Main")

def main():
    """Starts the EDR agent based on the detected operating system."""
    
    # 1. Windows: The agent runs as a Windows Service managed by pywin32.
    if platform.system() == "Windows":
        try:
            import win32serviceutil
            import servicemanager
            from agent_service import MiniEDRAgent
            
            # If no command line arguments are provided, it usually means 
            # the Service Control Manager (SCM) is starting the process.
            if len(sys.argv) == 1:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(MiniEDRAgent)
                servicemanager.StartServiceCtrlDispatcher()
            else:
                logger.info("Starting Windows Service handler (MiniEDRAgent)")
                # Standard pywin32 method to handle service commands like 'install', 'start', etc.
                win32serviceutil.HandleCommandLine(MiniEDRAgent)
        except ImportError:
            logger.error("pywin32 (win32serviceutil/servicemanager) not found.")
            sys.exit(1)
            
    # 2. Linux / Unix: The agent runs as a foreground process (usually managed by systemd).
    else:
        from agent_service_linux import run_agent, load_config
        logger.info("Starting Linux Agent logic flow")
        # Load server address from config.json before starting the loop.
        load_config()
        # Enter the observation loop.
        run_agent()

# Script execution entry point.
if __name__ == "__main__":
    main()

