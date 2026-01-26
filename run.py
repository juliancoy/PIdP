import os
from pathlib import Path
import json
import docker_utils
current_dir = Path(os.path.abspath(os.path.dirname(__file__)))
container_app_dir = "/app"


def run(prefix, NETWORK_NAME):
    docker_utils.initializeFiles(current_dir)
    with open(current_dir/"editme.py", 'r') as f:
        pidp_editme = eval(f.read())
    PIDP_DB = dict(
        image="postgres:15-alpine",
        detach=True,
        name=prefix + "PIdPdb",
        network=NETWORK_NAME,
        restart_policy={"Name": "always"},
        user="postgres",
        environment={
            "POSTGRES_PASSWORD": pidp_editme["PIDP_POSTGRES_PASSWORD"],
            "POSTGRES_USER": pidp_editme["PIDP_POSTGRES_USER"],
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
    PIDP_RUNDICT = dict(
        image="pidp",
        name=prefix+"pidp",
        volumes={
            str(current_dir): {"bind": container_app_dir, "mode": "rw"},
        },
        network=NETWORK_NAME,
        restart_policy={"Name": "always"},
        detach=True,
        command=[
            "uvicorn",
            "app.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
            "--reload",
            "--reload-dir",
            container_app_dir,
        ],
    )
    docker_utils.run_container(PIDP_RUNDICT)
