#!/usr/bin/env bash
# Runs on the Docker host. The first time, after `bash deploy.sh --no-restart` from your own machine:
#     cd ~/projects/threatmonitor && sudo bash install/install.sh
# Subcommands:
#     (none)   create /srv/threatmonitor, build the image, start the container, install the systemd unit (sudo; re-runnable)
#     enable   start at boot (sudo)                         revert  stop and remove the systemd units and container (sudo)
#     backup   nightly history backup to the router share: CIFS mount, timer, and one backup run now (sudo; re-runnable)
#     status   container and the last log lines (no sudo)
#     check-backup [archive]   unpack a backup (default: the newest on the share) in /var/tmp and check its database;
#                              the live data is not touched (no sudo)
#     restore <archive>        put a backup's history.db back: checked first, the current one kept aside (sudo)
set -euo pipefail

PROJECT=threatmonitor
SRV=/srv/$PROJECT
OWNER=1000   # the container's user (docker-compose.yml, user "1000:1000"), by number
PORT=5116
UNIT=/etc/systemd/system/$PROJECT.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # ~/projects/threatmonitor (staging) or /srv/threatmonitor/code

compose() { docker compose -f "$SRV/docker-compose.yml" "$@"; }
need_root() { [[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo bash ${BASH_SOURCE[0]} $*"; exit 1; }; }

provision() {
    mkdir -p "$SRV"/{code,data}
    cp -a "$SRC"/. "$SRV/code/"
    cp "$SRC"/Dockerfile "$SRC"/docker-compose.yml "$SRC"/requirements.txt "$SRC"/.dockerignore "$SRC"/.env.example "$SRV/"
    if [[ ! -f "$SRV/.env" ]]; then
        cp "$SRC"/.env.example "$SRV/.env"
        echo "Created $SRV/.env from .env.example. Set TM_SYSLOG_ALLOW there to your firewall's address (empty: syslog"
        echo "is accepted from anyone on the network), then: sudo docker compose -f $SRV/docker-compose.yml up -d"
    fi
    chown -R "$OWNER:$OWNER" "$SRV"
    chmod 600 "$SRV/.env"
}

build_and_up() {
    (cd "$SRV" && docker compose build && docker compose up -d)
    for _ in $(seq 1 20); do
        if curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1; then
            echo "ThreatMonitor answers: http://$(hostname -I | awk '{print $1}'):$PORT/"
            return
        fi
        sleep 3
    done
    echo "WARNING: no answer on :$PORT yet. See: docker compose -f $SRV/docker-compose.yml logs"
}

install_unit() {
    cp "$SRC/install/$PROJECT.service" "$UNIT"
    systemctl daemon-reload
}

# ---- nightly backup to an SMB share (e.g. the router's USB disk) ----
BACKUP_MNT=/mnt/$PROJECT-backup
CRED=/etc/smbcredentials/$PROJECT
FSTAB_TAG="# $PROJECT CIFS backup"

setup_cifs() {
    # //SMB_HOST/SMB_SHARE (a top-level folder on the SMB server), from .env; the share's name defaults below
    local host share user pass
    host=$(grep -E '^SMB_HOST=' "$SRV/.env" 2>/dev/null | cut -d= -f2- || true)
    share=$(grep -E '^SMB_SHARE=' "$SRV/.env" 2>/dev/null | cut -d= -f2- || true)
    user=$(grep -E '^SMB_USER=' "$SRV/.env" 2>/dev/null | cut -d= -f2- || true)
    pass=$(grep -E '^SMB_PASSWORD=' "$SRV/.env" 2>/dev/null | cut -d= -f2- || true)
    share=${share:-ThreatMonitor_Backup}
    mkdir -p /etc/smbcredentials
    if [[ -n "$user" && -n "$pass" ]]; then
        umask 077
        printf 'username=%s\npassword=%s\n' "$user" "$pass" > "$CRED"
    fi
    [[ -f "$CRED" ]] || { echo "ERROR: no SMB login: set SMB_USER / SMB_PASSWORD in $SRV/.env and re-run"; return 1; }
    chmod 0600 "$CRED"; chown root:root "$CRED"
    mkdir -p "$BACKUP_MNT"
    if ! grep -q "$FSTAB_TAG" /etc/fstab; then
        [[ -n "$host" ]] || { echo "ERROR: set SMB_HOST (the SMB server's address) in $SRV/.env and re-run"; return 1; }
        cp -p /etc/fstab "/etc/fstab.pre-$PROJECT.$(date +%F).bak"
        # mounted on first use (automount), giving up after 30 s, so a router that is down never holds up the boot
        printf '\n%s\n//%s/%s %s cifs credentials=%s,uid=1000,gid=1000,vers=2.0,iocharset=utf8,file_mode=0660,dir_mode=0770,_netdev,nofail,x-systemd.automount,x-systemd.mount-timeout=30 0 0\n' \
            "$FSTAB_TAG" "$host" "$share" "$BACKUP_MNT" "$CRED" >> /etc/fstab
        systemctl daemon-reload
    fi
    mountpoint -q "$BACKUP_MNT" || mount "$BACKUP_MNT" || { echo "ERROR: mount failed: sudo dmesg | grep -i cifs | tail"; return 1; }
    echo "share $(grep -A1 -F "$FSTAB_TAG" /etc/fstab | tail -n 1 | awk '{print $1}') mounted at $BACKUP_MNT"
}

install_backup() {
    command -v sqlite3 >/dev/null || apt-get install -y --no-install-recommends sqlite3
    install -m 0755 "$SRC/backup/backup-db.sh" "/usr/local/bin/$PROJECT-backup-db.sh"
    cp "$SRC/backup/$PROJECT-backup.service" "$SRC/backup/$PROJECT-backup.timer" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now "$PROJECT-backup.timer"
}

# ---- check a backup, restore one (the history database only: state.json holds today's live counts) ----
DATA=$SRV/data
TMP_DIR=

newest_backup() {
    { ls -1t "$BACKUP_MNT/$PROJECT"-{daily,monthly}-*.tar.gz 2>/dev/null || true; } | head -n 1
}

# an archive named on the command line: a path, or just its name on the share; none: the newest on the share
pick_backup() {
    local a=${1:-}
    if [[ -z "$a" ]]; then
        a=$(newest_backup)
        [[ -n "$a" ]] || { echo "ERROR: no backup found in $BACKUP_MNT (ls $BACKUP_MNT)" >&2; return 1; }
    elif [[ ! -f "$a" && -f "$BACKUP_MNT/$a" ]]; then
        a=$BACKUP_MNT/$a
    fi
    [[ -f "$a" ]] || { echo "ERROR: no such archive: $a" >&2; return 1; }
    echo "$a"
}

# unpack an archive's history.db into a fresh folder in /var/tmp ($TMP_DIR, removed on exit) and check it: prints what
# it holds, and fails unless SQLite's quick_check says ok
check_archive() {
    local archive=$1 db ok
    TMP_DIR=$(mktemp -d -p /var/tmp "$PROJECT-check-XXXX")
    trap 'rm -rf "$TMP_DIR"' EXIT
    echo "archive:       $(basename "$archive") ($(du -h "$archive" | cut -f1))"
    tar xzf "$archive" -C "$TMP_DIR" "$PROJECT/history.db" \
        || { echo "ERROR: could not unpack $PROJECT/history.db from it" >&2; return 1; }
    db=$TMP_DIR/$PROJECT/history.db
    ok=$(sqlite3 "$db" 'PRAGMA quick_check;' 2>&1 | head -n 5 || true)
    echo "quick_check:   $ok"
    [[ "$ok" == "ok" ]] || { echo "ERROR: the database in it is damaged" >&2; return 1; }
    echo "days:          $(sqlite3 "$db" "SELECT COUNT(*) || ' (' || IFNULL(MIN(day), '-') || ' to ' || IFNULL(MAX(day), '-') || ')' FROM daily;")"
    echo "events:        $(sqlite3 "$db" 'SELECT COUNT(*) FROM events;')"
    echo "newest event:  $(sqlite3 "$db" "SELECT IFNULL(datetime(MAX(ts), 'unixepoch', 'localtime'), '-') FROM events;")"
    echo "user_version:  $(sqlite3 "$db" 'PRAGMA user_version;')"
}

restore() {
    local archive=$1 stamp s
    echo ">> checking the backup first"
    check_archive "$archive" || { echo "Nothing was changed."; exit 1; }
    stamp=$(date +%Y%m%d-%H%M%S)
    echo ">> stopping the container"
    compose stop "$PROJECT"
    # the database and its write log belong together: moved aside as one set, never deleted. A -wal left next to the
    # restored file would be replayed into it by SQLite.
    echo ">> the current database, kept aside:"
    for s in "" -wal -shm; do
        if [[ -e "$DATA/history.db$s" ]]; then
            mv -- "$DATA/history.db$s" "$DATA/history.db.pre-restore.$stamp$s"
            echo "   $DATA/history.db.pre-restore.$stamp$s"
        fi
    done
    if [[ -e "$DATA/history.db-wal" || -e "$DATA/history.db-shm" ]]; then
        echo "ERROR: a -wal/-shm is still next to history.db; nothing restored. Start again with: compose up -d" >&2
        exit 1
    fi
    # the very file that passed the check; owned by the container's user (1000:1000)
    install -m 0644 -o 1000 -g 1000 "$TMP_DIR/$PROJECT/history.db" "$DATA/history.db" \
        || { echo "ERROR: could not put the restored file in place; the container is stopped." >&2; undo_hint "$stamp"; exit 1; }
    echo ">> restored $DATA/history.db from $(basename "$archive")"
    echo "   state.json (today's live counts) is left as it is: the dashboard keeps today's numbers so far"
    echo ">> starting the container"
    compose up -d
    for _ in $(seq 1 30); do
        if curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1; then
            echo ">> ThreatMonitor is healthy again: http://$(hostname -I | awk '{print $1}'):$PORT/history"
            undo_hint "$stamp"
            return
        fi
        sleep 3
    done
    echo "WARNING: /healthz did not answer OK within 90 s. See: docker compose -f $SRV/docker-compose.yml logs --tail 40" >&2
    undo_hint "$stamp"
    exit 1
}

undo_hint() {
    local stamp=$1
    echo "To undo: stop the container, move the restored history.db (and its -wal/-shm) away, put the old set back:"
    echo "   cd $DATA && sudo docker compose -f $SRV/docker-compose.yml stop $PROJECT"
    echo "   for s in '' -wal -shm; do [ -e history.db\$s ] && sudo mv history.db\$s history.db.restored.$stamp\$s;"
    echo "     [ -e history.db.pre-restore.$stamp\$s ] && sudo mv history.db.pre-restore.$stamp\$s history.db\$s; done"
    echo "   sudo docker compose -f $SRV/docker-compose.yml up -d"
}

case "${1:-}" in
    "")
        need_root
        provision
        build_and_up
        install_unit
        echo
        echo "Next steps:"
        echo "  1. OPNsense: System > Settings > Logging > Remote: send filter (and suricata) to $(hostname -I | awk '{print $1}'):5514 udp"
        echo "  2. At boot:  sudo bash $SRC/install/install.sh enable"
        ;;
    enable)
        need_root "$1"
        systemctl enable --now "$PROJECT.service"
        [[ -f /etc/systemd/system/$PROJECT-backup.timer ]] && systemctl enable --now "$PROJECT-backup.timer"
        systemctl --no-pager status "$PROJECT.service" || true
        ;;
    backup)
        need_root "$1"
        setup_cifs
        install_backup
        echo ">> first backup now:"
        systemctl start "$PROJECT-backup.service" && journalctl -u "$PROJECT-backup" -n 12 --no-pager
        systemctl list-timers "$PROJECT-backup.timer" --no-pager | head -3
        ;;
    revert)
        need_root "$1"
        systemctl disable --now "$PROJECT.service" 2>/dev/null || true
        systemctl disable --now "$PROJECT-backup.timer" 2>/dev/null || true
        rm -f "$UNIT" /etc/systemd/system/$PROJECT-backup.service /etc/systemd/system/$PROJECT-backup.timer
        echo "(the fstab line '$FSTAB_TAG' and $CRED are left in place)"
        systemctl daemon-reload
        compose down
        ;;
    status)
        compose ps
        echo
        compose logs --tail 40 "$PROJECT"
        echo
        curl -fsS "http://localhost:$PORT/api/debug" || true
        echo
        ;;
    check-backup)
        archive=$(pick_backup "${2:-}") || exit 1
        check_archive "$archive" || exit 1
        echo ">> it can be restored with: sudo bash $SRC/install/install.sh restore $(basename "$archive")"
        ;;
    restore)
        need_root "$@"
        [[ -n "${2:-}" ]] || { echo "Which backup? sudo bash ${BASH_SOURCE[0]} restore <archive> (see: ls $BACKUP_MNT)"; exit 2; }
        archive=$(pick_backup "$2") || exit 1
        restore "$archive"
        ;;
    *)
        echo "Unknown subcommand: $1 (none | enable | backup | revert | status | check-backup | restore)"
        exit 2
        ;;
esac
