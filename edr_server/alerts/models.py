"""
Database Schema for MiniEDR Server.
Defines the structure for endpoints (Machines), security events (Alerts), 
detection policies (DetectionRules), and active response operations (Tasks).
"""
from django.db import models
from django.contrib.auth.models import User

class Machine(models.Model):
    """Represents a unique endpoint (computer) running the MiniEDR agent."""
    hostname = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True) # Automatically updated on every heartbeat

    def __str__(self):
        return self.hostname


class Alert(models.Model):
    """Security detection event reported by an agent."""
    SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    machine = models.ForeignKey(Machine, on_delete=models.CASCADE)
    alert_type = models.CharField(max_length=100) # e.g., 'Suspicious Process', 'Network Alert'
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.alert_type} - {self.severity} on {self.machine.hostname}"

class DetectionRule(models.Model):
    """User-defined policy that the agent uses to flag suspicious activity."""
    RULE_TYPES = [
        ('process', 'Process Name'),
        ('cpu', 'CPU Threshold'),
        ('network', 'Suspicious IP/Host'),
    ]

    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    value = models.CharField(max_length=100) # The specific process name, IP, or % threshold
    severity = models.CharField(max_length=10)

    # Allow administrators to toggle rules without deleting them
    enabled = models.BooleanField(default=True) 
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.rule_type} - {self.value}"

class ProcessInventory(models.Model):
    """Cache of currently running processes on a specific machine."""
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name="processes")
    pid = models.IntegerField()
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=255, null=True, blank=True)
    memory_percent = models.FloatField(default=0)
    cpu_percent = models.FloatField(default=0)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.pid}) on {self.machine.hostname}"

class UserProfile(models.Model):
    """Extension of Django's built-in User model for Role-Based Access Control (RBAC)."""
    ROLE_CHOICES = [
        ('admin', 'Administrator'), # Full control
        ('analyst', 'Security Analyst'), # Can view and kill processes
        ('viewer', 'Guest Viewer'), # Read-only access
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='viewer')
    
    def __str__(self):
        return f"{self.user.username} ({self.role})"

class Task(models.Model):
    """Action requested by a user to be executed on a remote agent machine."""
    TASK_TYPES = [
        ('kill_process', 'Kill Process'),
        ('isolate_network', 'Isolate Network'),
        ('rejoin_network', 'Rejoin Network'),
        ('execute_script', 'Execute script'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending - Waiting for Heartbeat'),
        ('sent', 'Sent to Agent'),
        ('completed', 'Successfully Completed'),
        ('failed', 'Execution Failed'),
    ]

    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name="tasks")
    task_type = models.CharField(max_length=20, choices=TASK_TYPES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    parameters = models.JSONField(default=dict) # Key-value pairs like {'pid': 1234}
    result = models.TextField(null=True, blank=True) # Output or error message from the agent
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Audit trail: who initiated this action?
    triggered_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.task_type} for {self.machine.hostname} ({self.status})"
