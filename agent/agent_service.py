"""
Windows Service Wrapper for the MiniEDR agent.
Uses pywin32's ServiceFramework to manage the agent lifecycle.
"""
import win32serviceutil
import win32service
import win32event
import servicemanager
import requests
import json
import os
import time

# Core monitoring logic imported from the shared process_monitor module.
from process_monitor import monitor_processes, send_heartbeat, send_process_inventory, fetch_rules

class MiniEDRAgent(win32serviceutil.ServiceFramework):
    """
    Main Service class that allows the agent to be controlled via Windows Service Control Manager (SCM).
    Handles starting, stopping, and the main periodic execution loop.
    """
    _svc_name_ = "MiniEDRAgent"
    _svc_display_name_ = "Mini EDR Agent"
    _svc_description_ = "Mini EDR endpoint monitoring agent"

    def __init__(self, args):
        """Initializes the service framework and creates a stop event signal."""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        """Called by SCM when the service is requested to stop."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        # Signals the SvcDoRun event wait to terminate immediately.
        win32event.SetEvent(self.stop_event)
        servicemanager.LogInfoMsg("MiniEDR: Service stop request received.")

    def SvcDoRun(self):
        """Main service loop logic."""
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        servicemanager.LogInfoMsg("Mini EDR Agent Service Starting...")

        # Initialization of periodic task timers (seconds since epoch)
        last_rule_fetch = 0
        last_heartbeat = 0
        last_inventory_fetch = 0

        # Signal that the service is now running to the SCM.
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        servicemanager.LogInfoMsg("Mini EDR Agent Service Started")

        while self.running:
            try:
                now = time.time()

                # Action 1: Synchronize detection rules with the EDR Server.
                if now - last_rule_fetch > 60:
                    fetch_rules()
                    last_rule_fetch = now

                # Action 2: Report existence and health to the EDR Server.
                if now - last_heartbeat > 60:
                    send_heartbeat()
                    last_heartbeat = now

                # Action 3: Upload full snapshot of currently active processes.
                if now - last_inventory_fetch > 60:
                    send_process_inventory()
                    last_inventory_fetch = now

                # Action 4: Real-time scan of processes against local rules.
                monitor_processes()

            except Exception as e:
                # Log any unexpected failures to the Windows Event Log.
                servicemanager.LogErrorMsg(
                    f"MiniEDR: Critical error in monitoring cycle: {str(e)}"
                )

            # Wait for 5 seconds OR the stop event signal.
            # 5000ms is the scanning resolution for the agent.
            rc = win32event.WaitForSingleObject(self.stop_event, 5000)

            # Exit the loop if the Stop Event is signaled.
            if rc == win32event.WAIT_OBJECT_0:
                break

# Entry point for stand-alone execution or service management.
if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(MiniEDRAgent)