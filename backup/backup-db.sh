#!/usr/bin/env bash
# Nightly backup of ThreatMonitor's history to an SMB share (SMB_HOST / SMB_SHARE in .env, e.g. a folder on the
# router's USB disk, mounted at /mnt/threatmonitor-backup by install/install.sh backup):
# one consistent snapshot with sqlite3 VACUUM INTO (online while the monitor writes) to local disk first (SQLite
# cannot lock files on the CIFS mount), quick_check, then one tar.gz with the small state files, copied to the share.
# Not `.backup`: an online backup starts over each time another connection commits, and the monitor commits every
# second, so on a database of a few hundred MB it would never finish. VACUUM INTO reads one snapshot in one go.
# Staged in /var/tmp, not /tmp: /tmp on the box is a RAM disk (tmpfs, half the memory) and a year's copy is GBs.
#
# Why it matters: the history (every threat event, the per-day roll-ups, when each address was first seen) exists
# nowhere else; OPNsense only keeps a few weeks of its own logs.
# Retention (the router's USB disk is ~90 % full and this database grows by a few MB a day): the last 7 nightly
# copies + the copy made on the 1st of each month for about 6 months. Old copies are removed before the new one is
# written, so the share never has to hold one copy too many.

set -euo pipefail

PROJECT_NAME="threatmonitor"
DATA="/srv/${PROJECT_NAME}/data"
DB_PATH="${DATA}/history.db"
BACKUP_MOUNT="/mnt/${PROJECT_NAME}-backup"
KEEP_DAILY=7
KEEP_MONTHLY_DAYS=190
SPARE_MB=64     # free space wanted on the share beyond the new copy (+10 %)

if [[ ! -f "${DB_PATH}" ]]; then
    echo "ERROR: ${DB_PATH} not found." >&2
    exit 1
fi
if ! mountpoint -q "${BACKUP_MOUNT}"; then
    echo "ERROR: ${BACKUP_MOUNT} is not mounted. Check /etc/fstab and: sudo dmesg | grep -i cifs | tail" >&2
    exit 1
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
TMP_DIR="$(mktemp -d -p /var/tmp threatmonitor-backup-XXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir "${TMP_DIR}/threatmonitor"
# a copy made on the 1st of the month is kept for about 6 months (monthly), the rest for KEEP_DAILY copies
if [[ "$(date +%d)" == "01" ]]; then KIND="monthly"; else KIND="daily"; fi
FINAL_DEST="${BACKUP_MOUNT}/threatmonitor-${KIND}-${TS}.tar.gz"

echo ">> sqlite3 VACUUM INTO ${DB_PATH}"
sqlite3 -cmd ".timeout 60000" "${DB_PATH}" "VACUUM INTO '${TMP_DIR}/threatmonitor/history.db'"
echo ">> integrity check"
[[ "$(sqlite3 "${TMP_DIR}/threatmonitor/history.db" 'PRAGMA quick_check;')" == "ok" ]] \
    || { echo "ERROR: the copy failed quick_check" >&2; exit 1; }
# today's counters and the learned home/WAN/health state (each written atomically, so a plain copy is whole)
for f in state.json health.json home.json home_ips.json; do
    [[ -f "${DATA}/${f}" ]] && cp "${DATA}/${f}" "${TMP_DIR}/threatmonitor/"
done
echo ">> tar.gz"
tar czf "${TMP_DIR}/out.tar.gz" -C "${TMP_DIR}" threatmonitor

# only now that the new copy is known good: make room for it. A half-written copy from an earlier run that failed
# ends in .part, which the patterns below never match, so it is never counted as a backup.
rm -f -- "${BACKUP_MOUNT}"/threatmonitor-*.tar.gz.part
keep=${KEEP_DAILY}
if [[ "${KIND}" == "daily" ]]; then keep=$((KEEP_DAILY - 1)); fi   # the copy made now is the last of the KEEP_DAILY
echo ">> pruning: keep the newest ${KEEP_DAILY} daily copies, monthly copies for ${KEEP_MONTHLY_DAYS} days"
# (`|| true`: with no daily copy yet, ls fails, and pipefail would stop the script before the first copy is made)
{ ls -1t "${BACKUP_MOUNT}"/threatmonitor-daily-*.tar.gz 2>/dev/null || true; } | tail -n +$((keep + 1)) | while IFS= read -r f; do rm -f -- "$f"; done
find "${BACKUP_MOUNT}" -maxdepth 1 -name "threatmonitor-monthly-*.tar.gz" -mtime "+${KEEP_MONTHLY_DAYS}" -delete

size=$(stat -c %s "${TMP_DIR}/out.tar.gz")
need=$((size + size / 10 + SPARE_MB * 1024 * 1024))
free=$(df -B1 --output=avail "${BACKUP_MOUNT}" | tail -n 1 | tr -d ' ')
if (( free < need )); then
    echo "ERROR: not enough room on ${BACKUP_MOUNT}: the new copy is $((size / 1048576)) MB," \
         "$((need / 1048576)) MB wanted, $((free / 1048576)) MB free. No copy made tonight." >&2
    exit 1
fi
echo ">> cp -> ${FINAL_DEST} ($((size / 1048576)) MB, $((free / 1048576)) MB free)"
cp "${TMP_DIR}/out.tar.gz" "${FINAL_DEST}.part"
mv -- "${FINAL_DEST}.part" "${FINAL_DEST}"

echo ">> done."
ls -lh "${BACKUP_MOUNT}/" | tail -5
