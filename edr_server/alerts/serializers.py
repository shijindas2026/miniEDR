"""
Data Serializers for the MiniEDR API.
Converts Django ORM models into JSON format for the frontend and agent.
"""
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Alert, Machine, DetectionRule, ProcessInventory, Task, UserProfile

class TaskSerializer(serializers.ModelSerializer):
    """Serializes Active Response tasks (kill, isolate, etc.)."""
    class Meta:
        model = Task
        fields = "__all__"

class MachineSerializer(serializers.ModelSerializer):
    """Serializes Machine information including a calculated count of active processes."""
    processes_count = serializers.IntegerField(source='processes.count', read_only=True)
    class Meta:
        model = Machine
        fields = "__all__"

class AlertSerializer(serializers.ModelSerializer):
    """Serializes Security Alerts, nesting the associated machine data."""
    machine = MachineSerializer(read_only=True)
    class Meta:
        model = Alert
        fields = ["id", "machine", "alert_type", "severity", "description", "created_at"]

class DetectionRuleSerializer(serializers.ModelSerializer):
    """Serializes EDR scanning rules (Process name, CPU %, etc.)."""
    class Meta:
        model = DetectionRule
        fields = "__all__"

class ProcessInventorySerializer(serializers.ModelSerializer):
    """Serializes process metadata snapshots for a specific endpoint."""
    class Meta:
        model = ProcessInventory
        fields = "__all__"

class UserSerializer(serializers.ModelSerializer):
    """Serializes User accounts, flattening the Role from the UserProfile model."""
    role = serializers.CharField(source='profile.role', read_only=True)
    class Meta:
        model = User
        fields = ['id', 'username', 'role', 'is_active', 'last_login']