import os
import sys

from fastapi import APIRouter

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/debug")
def debug_info():
    # Intentional vuln: exposes environment variables and system info
    return {
        "environment": dict(os.environ),
        "python_version": sys.version,
        "platform": sys.platform,
    }
