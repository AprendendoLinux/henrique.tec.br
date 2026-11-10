import os

APP_VERSION = os.getenv("APP_VERSION", "dev-local")
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", str(8 * 3600)))
TRUSTED_DEVICE_DAYS = 30
