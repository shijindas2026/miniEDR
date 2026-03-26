"""
Linux Execution Engine for the MiniEDR agent.
Handles periodic tasks when running on Linux-like systems.
Usually invoked by main.py when a non-Windows OS is detected.
"""
import time
import os
import sys
import socket
import logging
from process_monitor import send_heartbeat, send_process_inventory, monitor_processes, load_config, fetch_rules

# Dedicated logger for Linux-specific agent operations.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MiniEDR-Linux")

def run_agent():
    """
    Main loop for the Linux agent. 
    Periodically executes monitoring, heartbeats, inventory updates, and rule fetches.
    """
    logger.info("MiniEDR Linux Agent implementation started.")
    
    # Store the last time each periodic task was successfully completed.
    last_heartbeat = 0
    last_inventory = 0
    last_rules = 0
    
    # Infinite observation loop.
    while True:
        try:
            now = time.time()
            
            # Action 1: Monitor Processes (Real-time detection)
            # This function scans active processes against locally stored rules.
            monitor_processes()
            
            # Action 2: Heartbeat (Every 60 seconds)
            # Notifies the server that this agent is online and checks for pending commands/tasks.
            if now - last_heartbeat > 60:
                logger.info("Synchronizing heartbeat with EDR server...")
                send_heartbeat()
                last_heartbeat = now
                
            # Action 3: Process Inventory (Every 60 seconds)
            # Sends a full list of running processes to the server for visibility.
            if now - last_inventory > 60:
                logger.info("Uploading process inventory snapshot...")
                send_process_inventory()
                last_inventory = now

            # Action 4: Fetch Rules (Every 60 seconds)
            # Downloads updated detection rules from the server.
            if now - last_rules > 60:
                logger.info("Checking for new detection rules...")
                fetch_rules()
                last_rules = now
            
            # Gentle sleep to prevent the loop from consuming 100% of a CPU core.
            time.sleep(1)
            
        except KeyboardInterrupt:
            # Allow clean exit when running in a terminal.
            logger.info("Agent shutdown requested by user (Ctrl+C).")
            break
        except Exception as e:
            # Catch unexpected errors to keep the agent running. 
            # Implements a 10s back-off to prevent rapid error looping.
            logger.error(f"Unexpected agent error: {str(e)}")
            time.sleep(10) 

if __name__ == "__main__":
    # If executed directly, ensure configuration is loaded from config.json.
    load_config()
    run_agent()

