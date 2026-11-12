
import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core.integrity import calculate_hash
from core.alerts import (
    initialize_database,
    log_event,
    get_baselines
)

MONITOR_FOLDER = "monitored_files"

# Current hashes observed while the monitor is running
file_hashes = {}

# Trusted hashes saved permanently in SQLite
trusted_baselines = {}


class SecurityMonitor(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory:
            return

        path = event.src_path
        new_hash = calculate_hash(path)

        if new_hash is None:
            print(f"[WARNING] Could not read created file: {path}")
            return

        old_runtime_hash = file_hashes.get(path)
        trusted_hash = trusted_baselines.get(path)

        if old_runtime_hash == new_hash:
            return

        if trusted_hash is not None:

            if new_hash == trusted_hash:
                log_event(
                    path,
                    "FILE_RESTORED",
                    old_hash=old_runtime_hash,
                    new_hash=new_hash
                )

                print(f"[INFO] FILE RESTORED: {path}")

            else:
                log_event(
                    path,
                    "INTEGRITY_VIOLATION",
                    old_hash=trusted_hash,
                    new_hash=new_hash
                )

                print(f"[ALERT] INTEGRITY VIOLATION: {path}")

        else:
            log_event(
                path,
                "FILE_CREATED",
                new_hash=new_hash
            )

            print(f"[ALERT] New file created: {path}")

        file_hashes[path] = new_hash

    def on_modified(self, event):
        if event.is_directory:
            return

        path = event.src_path
        new_hash = calculate_hash(path)

        if new_hash is None:
            print(f"[WARNING] Could not read modified file: {path}")
            return

        old_runtime_hash = file_hashes.get(path)
        trusted_hash = trusted_baselines.get(path)

        if old_runtime_hash == new_hash:
            return

        if trusted_hash is not None:

            if new_hash == trusted_hash:
                if old_runtime_hash != trusted_hash:
                    log_event(
                        path,
                        "FILE_RESTORED",
                        old_hash=old_runtime_hash,
                        new_hash=new_hash
                    )

                    print(f"[INFO] FILE RESTORED: {path}")

            else:
                log_event(
                    path,
                    "INTEGRITY_VIOLATION",
                    old_hash=trusted_hash,
                    new_hash=new_hash
                )

                print(f"[ALERT] INTEGRITY VIOLATION: {path}")

        else:
            log_event(
                path,
                "FILE_MODIFIED",
                old_hash=old_runtime_hash,
                new_hash=new_hash
            )

            print(f"[ALERT] Unregistered file modified: {path}")

        file_hashes[path] = new_hash

    def on_deleted(self, event):
        if event.is_directory:
            return

        path = event.src_path

        old_hash = trusted_baselines.get(path)

        if old_hash is None:
            old_hash = file_hashes.get(path)

        log_event(
            path,
            "FILE_DELETED",
            old_hash=old_hash
        )

        file_hashes.pop(path, None)

        print(f"[ALERT] File deleted: {path}")


def start_monitoring():

    if not os.path.isdir(MONITOR_FOLDER):
        raise FileNotFoundError(
            f"Monitoring folder not found: {MONITOR_FOLDER}"
        )

    initialize_database()

    global trusted_baselines
    trusted_baselines = get_baselines()

    def handle_walk_error(error):
        print(f"[WARNING] Startup folder access error: {error}")

    # Load current hashes for runtime comparison
    for root, directories, files in os.walk(
        MONITOR_FOLDER,
        onerror=handle_walk_error
    ):
        for filename in files:

            path = os.path.join(root, filename)
            current_hash = calculate_hash(path)

            if current_hash is None:
                print(f"[WARNING] Could not read startup file: {path}")
                continue

            file_hashes[path] = current_hash

            if path not in trusted_baselines:
                print(
                    f"[UNREGISTERED] File awaiting approval: {path}"
                )

    event_handler = SecurityMonitor()
    observer = Observer()

    observer.schedule(
        event_handler,
        MONITOR_FOLDER,
        recursive=True
    )

    observer.start()

    print("\nSentinelFIM is running!")
    print("Monitoring folder:", MONITOR_FOLDER)
    print("Trusted files:", len(trusted_baselines))
    print("Press CTRL + C to stop.\n")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping SentinelFIM...")

    finally:
        observer.stop()
        observer.join()
        print("SentinelFIM stopped successfully.")


if __name__ == "__main__":
    start_monitoring()
