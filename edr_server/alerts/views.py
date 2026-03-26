"""
MiniEDR Server View Controllers.
Contains both UI-rendering views (HTML) and RESTful API endpoints 
supporting the agent's telemetry and remote control.
"""
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.utils import timezone

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

from django.db.models import Count
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .serializers import (
    AlertSerializer, DetectionRuleSerializer, ProcessInventorySerializer, 
    TaskSerializer, UserSerializer
)
from .models import Alert, Machine, DetectionRule, ProcessInventory, Task, UserProfile
from django.contrib.auth.models import User

# -----------------------------
# UI/HTML Page Rendering Views
# -----------------------------

@login_required
def home(request):
    """Redirects the root URL to the monitoring dashboard."""
    return redirect('/dashboard/')


@login_required
def dashboard_page(request):
    """Renders the main EDR overview dashboard (Stats & Charts)."""
    return render(request, "dashboard.html")


@login_required
def alerts_page(request):
    """Displays a sortable table of all security alerts."""
    alerts = Alert.objects.select_related("machine").order_by("-created_at")

    return render(
        request,
        "alerts.html",
        {
            "alerts": alerts
        }
    )

@login_required
def alert_detail_page(request, alert_id):
    """Displays deep-dive information for a specific detection event."""
    try:
        alert = Alert.objects.select_related("machine").get(id=alert_id)
    except Alert.DoesNotExist:
        return HttpResponse("Alert record not found in database.", status=404)

    return render(
        request,
        "alert_detail.html",
        {
            "alert": alert
        }
    )


@login_required
def machines_page(request):
    return render(request, "machines.html")


@login_required
def rules_page(request):
    return render(request, "rules.html")

@login_required
def users_page(request):
    # Only Admin can access User management
    if not hasattr(request.user, 'profile') or request.user.profile.role != 'admin':
        return HttpResponse("Unauthorized. Admin privileges required.", status=403)
    return render(request, "users.html")


# Alert API (Used by Agents to submit detection events)
@method_decorator(csrf_exempt, name="dispatch")
class AlertListCreateView(APIView):
    """
    Handles alerts sent from EDR Agents.
    Incoming alerts trigger automatic machine registration if the hostname is new.
    """
    authentication_classes = []
    permission_classes = [AllowAny] # Agents often connect without per-view auth tokens

    def get(self, request):
        """Returns a JSON list of all alerts in the system."""
        alerts = Alert.objects.all().order_by("-created_at")
        serializer = AlertSerializer(alerts, many=True)
        return Response(serializer.data)

    def post(self, request):
        """Processes a new security alert from an endpoint."""
        hostname = request.data.get("hostname")
        ip_address = request.data.get("ip_address")
        alert_type = request.data.get("alert_type")
        severity = request.data.get("severity")
        description = request.data.get("description")

        if not hostname or not ip_address:
            return Response(
                {"error": "Hostname and IP required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Retrieve or create the Machine record associated with this hostname.
        try:
            machine = Machine.objects.get(hostname__iexact=hostname)
        except Machine.DoesNotExist:
            machine = Machine.objects.create(hostname=hostname, ip_address=ip_address)

        # Update IP in case it changed (DHCP).
        machine.ip_address = ip_address
        machine.save()

        # Record the alert in the database.
        Alert.objects.create(
            machine=machine,
            alert_type=alert_type,
            severity=severity,
            description=description
        )

        return Response(
            {"message": "Alert received and logged."},
            status=status.HTTP_201_CREATED
        )



# Dashboard API
class DashboardView(APIView):
    # Enforce login for UI
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({"error": "Auth required"}, status=401)

        today = timezone.now().date()

        total_alerts = Alert.objects.count()
        high_alerts = Alert.objects.filter(severity__iexact="High").count()
        medium_alerts = Alert.objects.filter(severity__iexact="Medium").count()
        low_alerts = Alert.objects.filter(severity__iexact="Low").count()

        total_machines = Machine.objects.count()
        alerts_today = Alert.objects.filter(created_at__date=today).count()

        top_machines = (
            Alert.objects
            .values("machine__hostname")
            .annotate(count=Count("id"))
            .order_by("-count")[:5]
        )

        top_alert_types = (
            Alert.objects
            .values("alert_type")
            .annotate(count=Count("id"))
            .order_by("-count")[:5]
        )

        latest_alerts = (
            Alert.objects
            .select_related("machine")
            .order_by("-created_at")[:10]
        )

        latest_alerts_data = [
            {
                "hostname": alert.machine.hostname,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "created_at": alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for alert in latest_alerts
        ]

        severity_distribution = {}

        if total_alerts > 0:
            severity_distribution = {
                "high_percent": round((high_alerts / total_alerts) * 100, 2),
                "medium_percent": round((medium_alerts / total_alerts) * 100, 2),
                "low_percent": round((low_alerts / total_alerts) * 100, 2),
            }

        data = {
            "total_alerts": total_alerts,
            "high_alerts": high_alerts,
            "medium_alerts": medium_alerts,
            "low_alerts": low_alerts,
            "total_machines": total_machines,
            "alerts_today": alerts_today,
            "severity_distribution": severity_distribution,
            "top_machines": list(top_machines),
            "top_alert_types": list(top_alert_types),
            "latest_alerts": latest_alerts_data,
        }

        return Response(data)


# Heartbeat API (Polling endpoint for Agents)
class HeartbeatView(APIView):
    """
    Protocol for agents to check-in.
    Updates 'last_seen' timestamp and delivers pending tasks (kill, isolate, etc.).
    """
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        hostname = request.data.get("hostname")
        ip_address = request.data.get("ip_address")

        if not hostname or not ip_address:
            return Response(
                {"error": "Hostname and IP required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Ensure machine exists and update its metadata.
        try:
            machine = Machine.objects.get(hostname__iexact=hostname)
        except Machine.DoesNotExist:
            machine = Machine.objects.create(hostname=hostname, ip_address=ip_address)

        machine.ip_address = ip_address
        machine.save() # Updates auto_now field 'last_seen'

        # Fetch any commands waiting for this machine.
        pending_tasks = Task.objects.filter(machine=machine, status='pending')
        tasks_data = []
        for t in pending_tasks:
            tasks_data.append({
                "id": t.id,
                "type": t.task_type,
                "parameters": t.parameters
            })
            # Transition status from 'pending' to 'sent' to avoid duplicates.
            t.status = 'sent'
            t.save()

        return Response({
            "message": "Heartbeat processed successfully.",
            "pending_tasks": tasks_data
        })


@method_decorator(csrf_exempt, name="dispatch")
class TaskCreateView(APIView):
    """
    Triggers an Active Response task on an endpoint.
    Implements Role-Based Access Control (RBAC) to restrict critical actions.
    """
    
    def post(self, request):
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=401)
            
        # RBAC Check: 'Viewer' role is read-only.
        if hasattr(request.user, 'profile') and request.user.profile.role == 'viewer':
            return Response({"error": "Viewer privileges restricted. Unauthorized to trigger tasks."}, status=403)

        hostname = request.data.get("hostname")
        task_type = request.data.get("task_type")
        parameters = request.data.get("parameters", {})

        if not hostname or not task_type:
            return Response({"error": "Hostname and task_type are required fields."}, status=400)

        # RBAC Check: 'Analyst' can only kill processes, not isolate machines or run scripts.
        role = request.user.profile.role if hasattr(request.user, 'profile') else 'viewer'
        if role == 'analyst' and task_type in ['execute_script', 'isolate_network']:
             return Response({"error": "Analyst role is restricted to 'Kill Process' only. System-wide changes require Admin."}, status=403)

        try:
            machine = Machine.objects.get(hostname__iexact=hostname)
            # Create the task record which will be picked up by the next heartbeat.
            task = Task.objects.create(
                machine=machine,
                task_type=task_type,
                parameters=parameters,
                triggered_by=request.user # Audit trail of who ran the command.
            )
            return Response({"message": "Task queued for delivery.", "task_id": task.id}, status=201)
        except Machine.DoesNotExist:
            return Response({"error": f"Target machine '{hostname}' not found."}, status=404)
        except Exception as e:
            return Response({"error": f"Internal task queueing error: {str(e)}"}, status=500)

class TaskResultView(APIView):

    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, task_id):
        status_val = request.data.get("status")
        result_val = request.data.get("result")

        try:
            task = Task.objects.get(id=task_id)
            task.status = status_val
            task.result = result_val
            task.save()
            return Response({"message": "Task updated"})
        except Task.DoesNotExist:
            return Response({"error": "Task not found"}, status=404)

class TaskListAPIView(APIView):
    def get(self, request):
        machine_hostname = request.query_params.get("hostname")
        if machine_hostname:
            tasks = Task.objects.filter(machine__hostname=machine_hostname).order_by("-created_at")
        else:
            tasks = Task.objects.all().order_by("-created_at")
            
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

# MachineListView API
class MachineListView(APIView):

    def get(self, request):
        if not request.user.is_authenticated:
            return Response({"error": "Auth required"}, status=401)
        machines = Machine.objects.all().order_by("-last_seen")

        data = [
            {
                "hostname": m.hostname,
                "ip_address": m.ip_address,
                "last_seen": m.last_seen
            }
            for m in machines
        ]

        return Response(data)
    

# Rule Management APIs
@method_decorator(csrf_exempt, name="dispatch")
class RuleListView(APIView):
    """Provides the detection rules JSON to both the UI and the EDR Agents."""
    authentication_classes = []
    permission_classes = [AllowAny] # Agents poll this frequently.

    def get(self, request):
        rules = DetectionRule.objects.all()
        serializer = DetectionRuleSerializer(rules, many=True)
        return Response(serializer.data)
    
class RuleCreateView(APIView):
    """Allows Administrators to add new detection patterns."""
    def post(self, request):
        if not request.user.is_authenticated or request.user.profile.role != 'admin':
            return Response({"error": "Administrator privileges required to create rules."}, status=403)
            
        serializer = DetectionRuleSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class RuleDeleteView(APIView):
    """Removes a detection rule by ID."""
    def delete(self, request, rule_id):
        if not request.user.is_authenticated or request.user.profile.role != 'admin':
            return Response({"error": "Administrator privileges required to delete rules."}, status=403)
        try:
            rule = DetectionRule.objects.get(id = rule_id)
            rule.delete()
            return Response({"message": "Rule successfully deleted."}, status=200)
        except DetectionRule.DoesNotExist:
            return Response({"error" : "Target rule not found."}, status=404)
        
class RuleUpdateView(APIView):
    """Modifies an existing detection rule (e.g., enabling/disabling)."""
    def put(self, request, rule_id):
        if not request.user.is_authenticated or request.user.profile.role != 'admin':
            return Response({"error": "Administrator privileges required to update rules."}, status=403)

        try:
            rule = DetectionRule.objects.get(id=rule_id)
        except DetectionRule.DoesNotExist:
            return Response({"error":"Target rule not found."}, status=404)

        serializer = DetectionRuleSerializer(rule, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=400)


# Inventory Management
@method_decorator(csrf_exempt, name="dispatch")
class ProcessInventoryUpdateView(APIView):
    """Endpoint for Agents to upload full process list snapshots."""
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        hostname = request.data.get("hostname")
        processes_data = request.data.get("processes", [])

        if not hostname:
            return Response({"error": "Hostname required for inventory sync."}, status=400)

        try:
            machine = Machine.objects.get(hostname__iexact=hostname)
        except Machine.DoesNotExist:
            return Response({"error": f"Machine '{hostname}' not registered."}, status=404)

        # To keep the database lean, we clear old snapshots before inserting the new one.
        ProcessInventory.objects.filter(machine=machine).delete()

        # Batch insertion for performance.
        new_processes = [
            ProcessInventory(
                machine=machine,
                pid=p.get("pid"),
                name=p.get("name"),
                username=p.get("username"),
                memory_percent=p.get("memory_percent", 0),
                cpu_percent=p.get("cpu_percent", 0)
            )
            for p in processes_data
        ]

        ProcessInventory.objects.bulk_create(new_processes)

        return Response({"message": f"Inventory synchronized with {len(new_processes)} process entries."})

class MachineProcessListView(APIView):
    """Retrieves the cached process list for a specific host."""
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, hostname):
        try:
            machine = Machine.objects.get(hostname__iexact=hostname)
            
            # Heuristic 'Offline' check: heartbeat missing for > 2 minutes.
            if (timezone.now() - machine.last_seen).total_seconds() > 120:
                return Response({
                    "error": "Client Offline", 
                    "message": f"{hostname} has not checked in for over 120 seconds. Displayed data may be stale."
                }, status=503)

            processes = ProcessInventory.objects.filter(machine=machine).order_by('name')
            serializer = ProcessInventorySerializer(processes, many=True)
            return Response(serializer.data)
        except Machine.DoesNotExist:
            return Response({"error": "Target machine record not found."}, status=404)


# User & RBAC Management APIs
class UserListCreateAPIView(APIView):
    """Admin-only view to list and create platform users."""
    def get(self, request):
        if not request.user.is_authenticated or request.user.profile.role != 'admin':
            return Response({"error": "Administrator status required."}, status=403)
        users = User.objects.all().order_by('username')
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request):
        if not request.user.is_authenticated or request.user.profile.role != 'admin':
            return Response({"error": "Administrator status required."}, status=403)
        
        username = request.data.get("username")
        password = request.data.get("password")
        role = request.data.get("role", "viewer")

        if User.objects.filter(username=username).exists():
            return Response({"error": "A user with this name already exists."}, status=400)

        user = User.objects.create_user(username=username, password=password)
        UserProfile.objects.create(user=user, role=role)
        
        return Response({"message": f"User account '{username}' created successfully."}, status=201)

class UserDeleteAPIView(APIView):
    """Admin-only endpoint to remove user accounts."""
    def delete(self, request, user_id):
        if not request.user.is_authenticated or request.user.profile.role != 'admin':
            return Response({"error": "Administrator status required."}, status=403)
        
        # Prevent 'Suicide' (Administrator deleting their own active account).
        if request.user.id == int(user_id):
            return Response({"error": "Self-deletion is prohibited for safety."}, status=400)
            
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return Response({"message": f"User account '{user.username}' deleted."})
        except User.DoesNotExist:
            return Response({"error": "Target user ID not found."}, status=404)

class UserPasswordResetView(APIView):
    """Allows Administrators to force a password change for any user."""
    def post(self, request, user_id):
        if not request.user.is_authenticated or request.user.profile.role != 'admin':
            return Response({"error": "Administrator status required."}, status=403)
        
        try:
            user = User.objects.get(id=user_id)
            new_password = request.data.get('password')
            if not new_password or len(new_password) < 4:
                return Response({"error": "Complexity requirement: Password must be at least 4 characters long."}, status=400)
            
            user.set_password(new_password)
            user.save()
            return Response({"message": f"Credentials successfully updated for {user.username}."})
        except User.DoesNotExist:
            return Response({"error": "Target user ID not found."}, status=404)

    
