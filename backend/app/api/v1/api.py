from fastapi import APIRouter
from app.api.v1.endpoints import auth, users, projects, members, config, database, agent_tasks, ssh_keys

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(projects.router, prefix="/projects", tags=["projects"])
api_router.include_router(members.router, prefix="/projects", tags=["members"])
api_router.include_router(config.router, prefix="/config", tags=["config"])
api_router.include_router(database.router, prefix="/database", tags=["database"])
api_router.include_router(agent_tasks.router, prefix="/agent-tasks", tags=["agent-tasks"])
api_router.include_router(ssh_keys.router, prefix="/ssh-keys", tags=["ssh-keys"])
