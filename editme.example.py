import os

BASE_ADDR = os.getenv("BASE_ADDR", "https://ballot-vm.local/")

PIDP_POSTGRES_PASSWORD = os.getenv("PIDP_POSTGRES_PASSWORD", "changeme")
PIDP_POSTGRES_USER = os.getenv("PIDP_POSTGRES_USER", "PIdP")
PIDP_SECRET_KEY = os.getenv("PIDP_SECRET_KEY", "changeme")

PIDP_GOOGLE_CLIENT_ID = os.getenv("PIDP_GOOGLE_CLIENT_ID", "google-client-id")
PIDP_GOOGLE_CLIENT_SECRET = os.getenv("PIDP_GOOGLE_CLIENT_SECRET", "google-client-secret")
PIDP_GOOGLE_REDIRECT_URI = os.getenv("PIDP_GOOGLE_REDIRECT_URI", BASE_ADDR + "auth/google/callback")

PIDP_GITHUB_CLIENT_ID = os.getenv("PIDP_GITHUB_CLIENT_ID", "github-client-id")
PIDP_GITHUB_CLIENT_SECRET = os.getenv("PIDP_GITHUB_CLIENT_SECRET", "github-client-secret")
PIDP_GITHUB_REDIRECT_URI = os.getenv("PIDP_GITHUB_REDIRECT_URI", BASE_ADDR + "auth/github/callback")

PIDP_FRONTEND_REDIRECT_URL = os.getenv("PIDP_FRONTEND_REDIRECT_URL", BASE_ADDR + "auth/callback")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minio")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "changeme")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "pidp-avatars")
MINIO_PUBLIC_BASE_URL = os.getenv("MINIO_PUBLIC_BASE_URL", BASE_ADDR + "s3")
