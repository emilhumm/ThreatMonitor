#!/usr/bin/env bash
# Deploy ThreatMonitor over ssh to the Docker host that runs it. Run from this folder (bash; Git Bash on Windows):
#     bash deploy.sh               # run the tests, sync the code to /srv/threatmonitor/code, restart the container
#                                  # and wait until /healthz answers
#     bash deploy.sh --build       # also rebuild the image (only when Dockerfile or requirements.txt changed)
#     bash deploy.sh --no-restart  # sync only (the very first time: then run install/install.sh on the box)
#     bash deploy.sh --no-test     # skip the test run
# The host is REMOTE_HOST=user@host, from the environment or from .deploy.env next to this file (not in git):
#     echo 'REMOTE_HOST=me@192.168.1.20' > .deploy.env
# The local copy is canonical; the box is a deploy target. Never edit code on the box.
# The commit deployed (git describe, -dirty with uncommitted changes) and the time go into VERSION next to the code.
set -euo pipefail

PORT=5116
BUILD=0; RESTART=1; TEST=1
for arg in "$@"; do
    case "$arg" in
        --build) BUILD=1 ;;
        --no-restart) RESTART=0 ;;
        --no-test) TEST=0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done
cd "$(dirname "$0")"
if [ -z "${REMOTE_HOST:-}" ] && [ -f .deploy.env ]; then
    REMOTE_HOST=$(grep -E '^REMOTE_HOST=' .deploy.env | tail -n 1 | cut -d= -f2- | tr -d '\r') || true
fi
[ -n "${REMOTE_HOST:-}" ] || { echo "Deploy where? Set REMOTE_HOST=user@host, or put that line in .deploy.env" >&2; exit 2; }
HOST=$REMOTE_HOST

if [ "$TEST" = 1 ]; then
    echo ">> Running the tests (skip with --no-test)..."
    PY=python
    if [ -x .venv/Scripts/python ]; then PY=.venv/Scripts/python; fi
    "$PY" -m pytest -q || { echo "Tests failed: nothing deployed." >&2; exit 1; }
    # again on the container's Python (3.13), when that environment is there (see README, Tests)
    if [ -x .venv313/Scripts/python ]; then
        echo ">> ... and on Python 3.13, as in the container"
        .venv313/Scripts/python -m pytest -q -p no:cacheprovider             || { echo "Tests failed on Python 3.13: nothing deployed." >&2; exit 1; }
    fi
fi

TARBALL=".deploy.tar.gz"
VERSION="$(git describe --always --dirty 2>/dev/null || echo unknown) $(date '+%Y-%m-%d %H:%M')"
trap 'rm -f "$TARBALL" VERSION' EXIT
echo "$VERSION" > VERSION
echo ">> Building deploy tarball ($VERSION)..."
tar czf "$TARBALL" \
    --warning=no-file-changed \
    --exclude='.git' --exclude='.claude' --exclude="$TARBALL" --exclude='.venv*' --exclude='.pytest_cache' \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='data' --exclude='.env' --exclude='.deploy.env' --exclude='*.jpg' \
    . || [[ $? -eq 1 ]]

echo ">> Copying to $HOST..."
ssh "$HOST" "mkdir -p projects"
scp -q "$TARBALL" "$HOST:projects/threatmonitor-deploy.tar.gz"

echo ">> Syncing on the box..."
rc=0
ssh "$HOST" bash -s -- "$BUILD" "$RESTART" <<'REMOTE' || rc=$?
set -euo pipefail
BUILD=$1; RESTART=$2
STAGE="$HOME/projects/threatmonitor"
SRV=/srv/threatmonitor
rm -rf "$STAGE" && mkdir -p "$STAGE"
tar xzf "$HOME/projects/threatmonitor-deploy.tar.gz" -C "$STAGE"
rm -f "$HOME/projects/threatmonitor-deploy.tar.gz"
echo "  staged in $STAGE"
if [ ! -d "$SRV/code" ]; then
    echo "  $SRV does not exist yet. Install with:"
    echo "    cd $STAGE && sudo bash install/install.sh"
    exit 10
fi
# mirror: files removed on the laptop disappear from the box too
(cd "$SRV/code" && find . -type f) | while IFS= read -r f; do
    [ -e "$STAGE/$f" ] || rm -f "$SRV/code/$f"
done
find "$SRV/code" -mindepth 1 -type d -empty -delete
cp -a "$STAGE/." "$SRV/code/"
# compose reads these from /srv/threatmonitor, not from code/
cp -a "$STAGE/Dockerfile" "$STAGE/docker-compose.yml" "$STAGE/requirements.txt" "$STAGE/.dockerignore" "$SRV/"
echo "  synced into $SRV/code and refreshed infra files"
[ "$RESTART" = 1 ] || exit 0
cd "$SRV"
if [ "$BUILD" = 1 ]; then
    docker compose build
fi
# start the new code exactly once: `up -d` recreates the container by itself when the image or the compose file
# changed (or starts it when it was stopped); only when it left the running container alone is a restart needed
before=$(docker inspect -f '{{.Id}} {{.State.StartedAt}}' threatmonitor 2>/dev/null || true)
docker compose up -d --remove-orphans
after=$(docker inspect -f '{{.Id}} {{.State.StartedAt}}' threatmonitor 2>/dev/null || true)
if [ "$before" = "$after" ]; then
    docker compose restart threatmonitor
    echo "  container restarted"
else
    echo "  container (re)started by compose"
fi
REMOTE
if [ "$rc" = 10 ]; then exit 0; fi   # not installed yet: the box said how
if [ "$rc" != 0 ]; then exit "$rc"; fi

if [ "$RESTART" = 1 ]; then
    # only a 200 counts: /healthz says 503 when the server runs but its main loop is stuck
    URL="http://${HOST#*@}:$PORT"
    echo ">> Waiting for $URL/healthz (up to 90 s: a start can first upgrade the database and recheck names)..."
    deadline=$((SECONDS + 90))
    until curl -fsS -m 5 "$URL/healthz" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "ERROR: $URL/healthz did not answer OK within 90 s. The container's last log lines:" >&2
            ssh "$HOST" "cd /srv/threatmonitor && docker compose logs --tail 40 threatmonitor" >&2 || true
            exit 1
        fi
        sleep 3
    done
    echo "  healthy, running $VERSION"
fi
echo ">> Done. ThreatMonitor: http://${HOST#*@}:$PORT/"
