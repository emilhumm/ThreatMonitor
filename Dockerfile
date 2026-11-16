# ThreatMonitor: one container that receives OPNsense syslog (5514 udp/tcp) and serves the globe (5116).
#
# The source is not COPY'd in: it is bind-mounted from /srv/threatmonitor/code (docker-compose.yml), so new code only
# needs `bash deploy.sh`, not a new image. Rebuild (`docker compose build`) when requirements.txt or this file changes.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    HOME=/home/app

# 1. System packages: python, tzdata (TZ in compose), curl (healthcheck).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip ca-certificates curl tzdata \
    && rm -rf /var/lib/apt/lists/*

# 2. Python packages from the manifest (the only file in the build context, see .dockerignore).
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt && rm /tmp/requirements.txt

# 3. Mount points for code and data (bind-mounted by compose, which runs it as uid 1000).
RUN mkdir -p /home/app/projects/threatmonitor /home/app/data
WORKDIR /home/app/projects/threatmonitor

# No CMD/ENTRYPOINT: compose starts `python3 -m threatmonitor` from the bind-mounted code.
