
import os
import sqlite3
from contextlib import closing

from core.integrity import calculate_hash
from core.alerts import get_baselines, log_event

MONITOR_FOLDER = "monitored_files"
DB_PATH = "database/security.db"


def already_reported(path, current_hash):
    with closing(sqlite3.connect(DB_PATH)) as connection:
        last_event = connection.execute("""
            SELECT new_hash
            FROM security_events
            WHERE file_path = ?
            AND event_type = 'INTEGRITY_VIOLATION'
            ORDER BY id DESC
            LIMIT 1
        """, (path,)).fetchone()

    return last_event is not None and last_event[0] == current_hash


def already_reported_missing(path):
    with closing(sqlite3.connect(DB_PATH)) as connection:
        last_event = connection.execute("""
            SELECT event_type
            FROM security_events
            WHERE file_path = ?
            ORDER BY id DESC
            LIMIT 1
        """, (path,)).fetchone()

    return last_event is not None and last_event[0] == "FILE_DELETED"


def scan_files():

    if not os.path.isdir(MONITOR_FOLDER):
        raise FileNotFoundError(
            f"Monitoring folder not found: {MONITOR_FOLDER}"
        )

    trusted_baselines = get_baselines()
    results = []
    current_files = set()
    scan_errors = []

    def handle_walk_error(error):
        scan_errors.append(error)
        print(f"[WARNING] Could not access folder: {error}")

    for root, directories, files in os.walk(
        MONITOR_FOLDER,
        onerror=handle_walk_error
    ):
        for filename in files:

            path = os.path.join(root, filename)
            current_files.add(path)

            current_hash = calculate_hash(path)

            if current_hash is None:
                print(f"[WARNING] Could not read file: {path}")
                continue

            trusted_hash = trusted_baselines.get(path)

            if trusted_hash is None:
                status = "UNREGISTERED"

            elif current_hash != trusted_hash:
                status = "INTEGRITY_VIOLATION"

                if not already_reported(path, current_hash):
                    log_event(
                        path,
                        "INTEGRITY_VIOLATION",
                        old_hash=trusted_hash,
                        new_hash=current_hash
                    )

            else:
                status = "VERIFIED"

            results.append({
                "file_path": path,
                "status": status,
                "current_hash": current_hash,
                "trusted_hash": trusted_hash
            })

    # Only report missing files when folder scanning was complete.
    if not scan_errors:

        for path, trusted_hash in trusted_baselines.items():

            if path not in current_files:

                if not already_reported_missing(path):
                    log_event(
                        path,
                        "FILE_DELETED",
                        old_hash=trusted_hash
                    )

                results.append({
                    "file_path": path,
                    "status": "MISSING",
                    "current_hash": None,
                    "trusted_hash": trusted_hash
                })

    else:
        print(
            "[WARNING] Some folders could not be scanned. "
            "Missing-file checks were skipped to prevent false alerts."
        )

    return results
