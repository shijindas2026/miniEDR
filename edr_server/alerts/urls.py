"""
URL Configuration for the Alerts app.
Maps web requests to the appropriate UI views or API controllers.
"""
from django.urls import path
from django.shortcuts import redirect

from .views import (
    AlertListCreateView,
    DashboardView,
    HeartbeatView,
    RuleListView,
    RuleCreateView,
    MachineListView,
    RuleDeleteView,
    RuleUpdateView,
    ProcessInventoryUpdateView,
    MachineProcessListView,
    TaskCreateView,
    TaskResultView,
    TaskListAPIView,

    dashboard_page,
    alerts_page,
    alert_detail_page,
    machines_page,
    rules_page,
    users_page,
)

from .views import (
    UserListCreateAPIView,
    UserDeleteAPIView,
    UserPasswordResetView,
)

urlpatterns = [

    # -------- UI PAGES (HTML Rendering) --------
    
    # Root redirect (Convenience)
    path("", lambda request: redirect("/dashboard/")),
    
    # Primary Navigation Pages
    path("dashboard/", dashboard_page, name="dashboard-page"),
    path("alerts/", alerts_page, name="alerts-page"),
    path("alerts/<int:alert_id>/", alert_detail_page, name="alert-detail"),
    path("machines/", machines_page, name="machines-page"),
    path("rules/", rules_page, name="rules-page"),
    path("users/", users_page, name="users-page"),


    # -------- API ENDPOINTS (JSON Data) --------

    # Core EDR Telemetry & Health
    path("api/alerts/", AlertListCreateView.as_view(), name="alert-list-create"),
    path("api/dashboard/", DashboardView.as_view(), name="dashboard-api"),
    path("api/heartbeat/", HeartbeatView.as_view(), name="heartbeat"),
    
    # Detection Policy Management
    path("api/rules/", RuleListView.as_view(), name="rule-list"),
    path("api/rules/create/", RuleCreateView.as_view(), name="rule-create"),
    path("api/rules/<int:rule_id>/delete/", RuleDeleteView.as_view()),
    path("api/rules/<int:rule_id>/update/", RuleUpdateView.as_view()),
    
    # Asset & Process Visibility
    path("api/machines/", MachineListView.as_view(), name="machine-list"),
    path("api/inventory/update/", ProcessInventoryUpdateView.as_view(), name="inventory-update"),
    path("api/inventory/<str:hostname>/", MachineProcessListView.as_view(), name="machine-inventory"),

    # Platform Administration (User RBAC)
    path("api/users/", UserListCreateAPIView.as_view(), name="api-user-list"),
    path("api/users/<int:user_id>/delete/", UserDeleteAPIView.as_view(), name="api-user-delete"),
    path("api/users/<int:user_id>/reset-password/", UserPasswordResetView.as_view(), name="api-user-reset"),

    # Active Response Tasking (Remote Actions)
    path("api/tasks/", TaskListAPIView.as_view(), name="task-list"),
    path("api/tasks/create/", TaskCreateView.as_view(), name="task-create"),
    path("api/tasks/<int:task_id>/result/", TaskResultView.as_view(), name="task-result"),
]