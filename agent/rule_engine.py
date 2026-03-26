"""
MiniEDR Rule Engine.
Parses the rules.json file and organizes rules for fast lookups.
Supported categories: Process, CPU usage, and Network connections.
"""
import json
import os
try:
    import servicemanager
except ImportError:
    class MockServiceManager:
        def LogInfoMsg(self, msg): print(f"INFO: {msg}")
        def LogErrorMsg(self, msg): print(f"ERROR: {msg}")
    servicemanager = MockServiceManager()


from paths import get_rule_path

# Path to the local JSON rules file updated by the server
RULE_FILE = get_rule_path()

def load_rules():
    """Reads rules from the local storage file and parses them into categorized dictionaries."""
    
    # Check if the rules file exists; if not, return empty dictionaries
    if not os.path.exists(RULE_FILE):
        servicemanager.LogErrorMsg(
            f"MiniEDR: rules.json not found at {RULE_FILE}"
        )
        return {"process": {}, "cpu": {}, "network": {}}

    try:
        # Load the data from the JSON file
        with open(RULE_FILE, "r") as f:
            data = json.load(f)

        # Initialize the rules dictionary by category
        rules = {"process": {}, "cpu": {}, "network": {}}

        # Iterate through loaded rules and categorize them
        for rule in data:
            # Skip any rule that is explicitly marked as disabled
            if not rule.get("enabled", True):
                continue

            rule_type = rule.get("rule_type")
            value = rule.get("value")

            # Map the rule to its category (process name, IP address, or CPU percentage)
            if rule_type in rules and value:
                # Store by category for O(1) lookups during monitoring
                rules[rule_type][value.lower()] = {
                    "severity": rule.get("severity", "Medium"),
                    "id": rule.get("id")
                }

        return rules

    except Exception as e:
        # Log parsing errors to the system log (Windows Event Log or equivalent via Mock)
        servicemanager.LogErrorMsg(
            f"MiniEDR: Error loading rules - {str(e)}"
        )
        # Return empty data structure on failure
        return {"process": {}, "cpu": {}, "network": {}}