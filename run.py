import os
from pathlib import Path
import json
import sys
import docker_utils
current_dir = Path(os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, str(current_dir))
container_app_dir = "/app"


def run(prefix, NETWORK_NAME):
    docker_utils.initializeFiles(current_dir)
    import pidp_editme
    PIDP_DB = dict(
        image="postgres:15-alpine",
        detach=True,
        name=prefix + "pidpdb",
        network=NETWORK_NAME,
        restart_policy={"Name": "always"},
        user="postgres",
        environment={
            "POSTGRES_PASSWORD": pidp_editme.PIDP_POSTGRES_PASSWORD,
            "POSTGRES_USER": pidp_editme.PIDP_POSTGRES_USER,
            "POSTGRES_DB": "PIdP",
        },
        volumes={
            prefix + "PIdP_POSTGRES": {
                "bind": "/var/lib/postgresql/data",
                "mode": "rw",
            }
        },
        healthcheck={
            "test": ["CMD-SHELL", "pg_isready"],
            "interval": 5000000000,  # 5s in nanoseconds
            "timeout": 5000000000,  # 5s in nanoseconds
            "retries": 10,
        },
    )
    PIDP_DB_URL = f"postgresql+asyncpg://{pidp_editme.PIDP_POSTGRES_USER}:{pidp_editme.PIDP_POSTGRES_PASSWORD}@{prefix}pidpdb:5432/PIdP"
    PIDP_RUNDICT = dict(
        image="pidp",
        name=prefix+"pidp",
        volumes={
            str(current_dir): {"bind": container_app_dir, "mode": "rw"},
        },
        environment={
            "DATABASE_URL": PIDP_DB_URL,
            "SECRET_KEY": pidp_editme.PIDP_SECRET_KEY,
            "AUTO_CREATE_TABLES": "true",
            "WATCHFILES_FORCE_POLLING": "true",
            "FRONTEND_REDIRECT_URL": pidp_editme.PIDP_FRONTEND_REDIRECT_URL,
            "GOOGLE_CLIENT_ID": pidp_editme.PIDP_GOOGLE_CLIENT_ID,
            "GOOGLE_CLIENT_SECRET": pidp_editme.PIDP_GOOGLE_CLIENT_SECRET,
            "GOOGLE_REDIRECT_URI": pidp_editme.PIDP_GOOGLE_REDIRECT_URI,
            "GITHUB_CLIENT_ID": pidp_editme.PIDP_GITHUB_CLIENT_ID,
            "GITHUB_CLIENT_SECRET": pidp_editme.PIDP_GITHUB_CLIENT_SECRET,
            "GITHUB_REDIRECT_URI": pidp_editme.PIDP_GITHUB_REDIRECT_URI,
            "JWT_PRIVATE_KEY": os.getenv("PIDP_JWT_PRIVATE_KEY"),
            "JWT_PUBLIC_KEY": os.getenv("PIDP_JWT_PUBLIC_KEY"),
            "JWT_ISSUER": os.getenv("PIDP_JWT_ISSUER"),
            "JWT_AUDIENCE": os.getenv("PIDP_JWT_AUDIENCE"),
            "MINIO_ENDPOINT": pidp_editme.MINIO_ENDPOINT,
            "MINIO_ACCESS_KEY": pidp_editme.MINIO_ACCESS_KEY,
            "MINIO_SECRET_KEY": pidp_editme.MINIO_SECRET_KEY,
            "MINIO_BUCKET": pidp_editme.MINIO_BUCKET,
            "MINIO_PUBLIC_BASE_URL": pidp_editme.MINIO_PUBLIC_BASE_URL,
        },
        network=NETWORK_NAME,
        restart_policy={"Name": "always"},
        detach=True,
        command=[
            "uvicorn",
            "main:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--reload",
            "--reload-dir",
            container_app_dir,
        ],
    )
    docker_utils.run_container(PIDP_DB)
    docker_utils.wait_for_db(NETWORK_NAME,db_url=PIDP_DB_URL,db_user=pidp_editme.PIDP_POSTGRES_USER)
    docker_utils.run_container(PIDP_RUNDICT)
