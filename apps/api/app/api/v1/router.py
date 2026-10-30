"""V1 API router aggregation."""

from fastapi import APIRouter

from apps.api.app.api.v1.analysis import router as analysis_router
from apps.api.app.api.v1.analyze import router as analyze_router
from apps.api.app.api.v1.audit import router as audit_router
from apps.api.app.api.v1.auth import router as auth_router
from apps.api.app.api.v1.blue import router as blue_router
from apps.api.app.api.v1.clients import router as clients_router
from apps.api.app.api.v1.dashboard import router as dashboard_router
from apps.api.app.api.v1.evaluations import router as evaluations_router
from apps.api.app.api.v1.improvement import router as improvement_router
from apps.api.app.api.v1.intelligence import router as intelligence_router
from apps.api.app.api.v1.lab import router as lab_router
from apps.api.app.api.v1.policy import router as policy_router
from apps.api.app.api.v1.releases import router as releases_router
from apps.api.app.api.v1.reports import router as reports_router
from apps.api.app.api.v1.system import router as system_router
from apps.api.app.api.v1.telemetry import router as telemetry_router
from apps.api.app.api.v1.updates import router as updates_router

v1_router = APIRouter(prefix="/api/v1")
v1_router.include_router(system_router)
v1_router.include_router(auth_router)
v1_router.include_router(dashboard_router)
v1_router.include_router(clients_router)
v1_router.include_router(audit_router)
v1_router.include_router(analysis_router)
v1_router.include_router(analyze_router)
v1_router.include_router(blue_router)
v1_router.include_router(evaluations_router)
v1_router.include_router(improvement_router)
v1_router.include_router(intelligence_router)
v1_router.include_router(lab_router)
v1_router.include_router(reports_router)
v1_router.include_router(policy_router)
v1_router.include_router(releases_router)
v1_router.include_router(telemetry_router)
v1_router.include_router(updates_router)
