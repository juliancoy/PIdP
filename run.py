import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import docker_utils

current_dir = Path(os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, str(current_dir))
container_app_dir = "/app"
control_state_file = current_dir / "frontend" / ".control-state.json"

DEFAULT_PROD_IMAGE = "ghcr.io/juliancoy/pidp:latest"


def _read_control_state() -> dict:
    if not control_state_file.is_file():
        return {}
    try:
        return json.loads(control_state_file.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_control_state(patch: dict) -> None:
    state = _read_control_state()
    state.update(patch)
    state["updated_at"] = datetime.utcnow().isoformat() + "Z"
    control_state_file.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _resolve_prod_image() -> str:
    env_override = (os.getenv("PIDP_PROD_IMAGE") or "").strip()
    if env_override:
        return env_override
    state = _read_control_state()
    from_control = (state.get("backend_image_ref") or "").strip()
    if from_control:
        return from_control
    return DEFAULT_PROD_IMAGE


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _docker_image_exists(image_ref: str) -> bool:
    proc = subprocess.run(
        ["docker", "image", "inspect", image_ref],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def _ensure_prod_image_available(requested_image: str) -> tuple[str, str]:
    skip_pull = _env_truthy("PIDP_SKIP_PROD_PULL", default=False)
    fallback_build = _env_truthy("PIDP_ALLOW_LOCAL_PROD_BUILD", default=True)

    if not skip_pull:
        pull_proc = subprocess.run(["docker", "pull", requested_image])
        if pull_proc.returncode == 0:
            return requested_image, "pulled"
        print(f"Warning: failed to pull prod image {requested_image}")
    else:
        print("Skipping prod image pull because PIDP_SKIP_PROD_PULL is enabled")

    if _docker_image_exists(requested_image):
        print(f"Using cached local prod image: {requested_image}")
        return requested_image, "local-cache"

    if fallback_build:
        local_tag = os.getenv("PIDP_PROD_LOCAL_IMAGE", "pidp-prod:local")
        print(
            "Prod image is unavailable via registry/local cache; "
            f"building local fallback image as {local_tag}"
        )
        subprocess.check_call(
            [
                "docker",
                "build",
                "-f",
                str(current_dir / "Dockerfile"),
                "-t",
                local_tag,
                str(current_dir),
            ]
        )
        return local_tag, "local-build-fallback"

    raise RuntimeError(
        "Unable to start prod container: registry pull failed and no local image exists. "
        "Either make GHCR package readable, run `docker login ghcr.io`, set PIDP_PROD_IMAGE "
        "to an accessible image, or enable PIDP_ALLOW_LOCAL_PROD_BUILD=true."
    )


def _common_env(pidp_editme, db_url: str) -> dict:
    return {
        "DATABASE_URL": db_url,
        "SECRET_KEY": pidp_editme.PIDP_SECRET_KEY,
        "AUTO_CREATE_TABLES": "true",
        "ADMIN_EMAILS": os.getenv("PIDP_ADMIN_EMAILS", ""),
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
    }


def _normalize_public_base(url: str | None) -> str | None:
    value = (url or "").strip()
    if not value:
        return None
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    if not value.endswith("/"):
        value += "/"
    return value


def _derive_dev_base(prod_base: str | None) -> str | None:
    normalized = _normalize_public_base(prod_base)
    if not normalized:
        return None
    if "://pidp." in normalized:
        return normalized.replace("://pidp.", "://dev.pidp.", 1)
    return normalized


def _oauth_urls(base_url: str | None) -> dict[str, str | None]:
    normalized = _normalize_public_base(base_url)
    if not normalized:
        return {
            "google": None,
            "github": None,
            "frontend": None,
        }
    return {
        "google": normalized + "auth/google/callback",
        "github": normalized + "auth/github/callback",
        "frontend": normalized + "auth/callback",
    }


def _default_allowed_origins(prod_base: str | None, dev_base: str | None) -> str:
    origins: list[str] = []
    for base in (prod_base, dev_base):
        normalized = _normalize_public_base(base)
        if not normalized:
            continue
        origin = normalized.rstrip("/")
        if origin not in origins:
            origins.append(origin)
        if "://pidp." in origin:
            portal_origin = origin.replace("://pidp.", "://portal.", 1)
            if portal_origin not in origins:
                origins.append(portal_origin)
        if "://dev.pidp." in origin:
            dev_portal_origin = origin.replace("://dev.pidp.", "://dev.portal.", 1)
            if dev_portal_origin not in origins:
                origins.append(dev_portal_origin)
    return ",".join(origins)


def run(prefix, network_name):
    docker_utils.initializeFiles(current_dir)
    import pidp_editme

    db_name = prefix + "pidpdb"
    db_url = (
        f"postgresql+asyncpg://{pidp_editme.PIDP_POSTGRES_USER}:"
        f"{pidp_editme.PIDP_POSTGRES_PASSWORD}@{db_name}:5432/PIdP"
    )
    env_base = _common_env(pidp_editme, db_url)
    configured_prod_base = (
        os.getenv("PIDP_PROD_PUBLIC_BASE_URL")
        or getattr(pidp_editme, "PIDP_BASE_ADDR", None)
        or getattr(pidp_editme, "BASE_ADDR", None)
    )
    configured_dev_base = os.getenv("PIDP_DEV_PUBLIC_BASE_URL") or _derive_dev_base(configured_prod_base)
    prod_oauth = _oauth_urls(configured_prod_base)
    dev_oauth = _oauth_urls(configured_dev_base)
    configured_allowed_origins = (os.getenv("PIDP_ALLOWED_ORIGINS") or "").strip()
    env_base["ALLOWED_ORIGINS"] = configured_allowed_origins or _default_allowed_origins(
        configured_prod_base,
        configured_dev_base,
    )

    pidp_db = {
        "image": "postgres:15-alpine",
        "detach": True,
        "name": db_name,
        "network": network_name,
        "restart_policy": {"Name": "always"},
        "user": "postgres",
        "environment": {
            "POSTGRES_PASSWORD": pidp_editme.PIDP_POSTGRES_PASSWORD,
            "POSTGRES_USER": pidp_editme.PIDP_POSTGRES_USER,
            "POSTGRES_DB": "PIdP",
        },
        "volumes": {
            prefix + "PIdP_POSTGRES": {"bind": "/var/lib/postgresql/data", "mode": "rw"}
        },
        "healthcheck": {
            "test": ["CMD-SHELL", "pg_isready"],
            "interval": 5000000000,
            "timeout": 5000000000,
            "retries": 10,
        },
    }

    # Prod: release artifact image, no bind mount, no reload.
    prod_image = _resolve_prod_image()
    pidp_prod = {
        "image": prod_image,
        "name": prefix + "pidp",
        "environment": {
            **env_base,
            "GOOGLE_REDIRECT_URI": prod_oauth["google"] or env_base.get("GOOGLE_REDIRECT_URI"),
            "GITHUB_REDIRECT_URI": prod_oauth["github"] or env_base.get("GITHUB_REDIRECT_URI"),
            "FRONTEND_REDIRECT_URL": prod_oauth["frontend"] or env_base.get("FRONTEND_REDIRECT_URL"),
            "BACKEND_IMAGE_RUNNING": prod_image,
        },
        "network": network_name,
        "restart_policy": {"Name": "always"},
        "detach": True,
        "command": [
            "uvicorn",
            "main:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
    }

    # Dev: local code with watcher/reload.
    pidp_dev = {
        "image": os.getenv("PIDP_DEV_IMAGE", "pidp-dev"),
        "name": prefix + "pidp-dev",
        "build": {"context": str(current_dir), "dockerfile": "Dockerfile"},
        "rebuild_image_on_restart": True,
        "volumes": {str(current_dir): {"bind": container_app_dir, "mode": "rw"}},
        "environment": {
            **env_base,
            "GOOGLE_REDIRECT_URI": dev_oauth["google"] or env_base.get("GOOGLE_REDIRECT_URI"),
            "GITHUB_REDIRECT_URI": dev_oauth["github"] or env_base.get("GITHUB_REDIRECT_URI"),
            "FRONTEND_REDIRECT_URL": dev_oauth["frontend"] or env_base.get("FRONTEND_REDIRECT_URL"),
            "WATCHFILES_FORCE_POLLING": "true",
            "BACKEND_IMAGE_RUNNING": "dev-local-build",
        },
        "network": network_name,
        "restart_policy": {"Name": "always"},
        "detach": True,
        "command": [
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
    }

    resolved_prod_image, image_source = _ensure_prod_image_available(prod_image)
    print(f"Using prod release image: {resolved_prod_image} ({image_source})")
    print(f"Prod OAuth callback base: {_normalize_public_base(configured_prod_base) or 'unchanged'}")
    print(f"Dev OAuth callback base: {_normalize_public_base(configured_dev_base) or 'unchanged'}")
    pidp_prod["image"] = resolved_prod_image
    pidp_prod["environment"]["BACKEND_IMAGE_RUNNING"] = resolved_prod_image

    docker_utils.run_container(pidp_db)
    docker_utils.wait_for_db(network_name, db_url=db_url, db_user=pidp_editme.PIDP_POSTGRES_USER)
    docker_utils.run_container(pidp_prod)
    docker_utils.run_container(pidp_dev)
    _write_control_state(
        {
            "backend_last_rollout_at": datetime.utcnow().isoformat() + "Z",
            "backend_last_rollout_image": resolved_prod_image,
            "backend_rollout_requested_at": None,
        }
    )


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        prefix = sys.argv[1]
        network_name = sys.argv[2]
    else:
        prefix = ""
        network_name = "arkavo"
    run(prefix, network_name)
