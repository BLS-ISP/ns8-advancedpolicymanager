"""API router collection."""

from app.routes.agent import router as agent_router
from app.routes.assignments import router as assignments_router
from app.routes.dashboard import router as dashboard_router
from app.routes.devices import router as devices_router
from app.routes.enrollment import router as enrollment_router
from app.routes.policies import router as policies_router
from app.routes.simulator import router as simulator_router

__all__ = [
    "agent_router",
    "assignments_router",
    "dashboard_router",
    "devices_router",
    "enrollment_router",
    "policies_router",
    "simulator_router",
]
