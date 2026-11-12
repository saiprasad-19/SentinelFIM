from contextlib import closing
import sqlite3
from datetime import datetime

DB_PATH = "database/security.db"

# Severity assigned to each security event
SEVERITY_LEVELS = {
    "FILE_CREATED": "MEDIUM",
    "FILE_MODIFIED": "HIGH",
    "INTEGRITY_VIOLATION": "HIGH",
    "FILE_DELETED": "HIGH",
    "FILE_RESTORED": "LOW"
}

def initialize_database():
    with closing(sqlite3.connect(DB_PATH)) as connection:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    severity TEXT NOT NULL DEFAULT 'LOW'
                )
            """)

            columns = [
                row[1] for row in
                connection.execute("PRAGMA table_info(security_events)")
            ]

            if "severity" not in columns:
                connection.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN severity TEXT NOT NULL DEFAULT 'LOW'
                """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS file_baselines (
                    file_path TEXT PRIMARY KEY,
                    file_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)



def log_event(file_path, event_type, old_hash=None, new_hash=None):
    severity = SEVERITY_LEVELS.get(event_type, "LOW")

    with closing(sqlite3.connect(DB_PATH)) as connection:
        with connection:
            connection.execute("""
                INSERT INTO security_events
                (file_path, event_type, event_time, old_hash, new_hash, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                file_path,
                event_type,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                old_hash,
                new_hash,
                severity
            ))




def save_baseline(file_path, file_hash):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with closing(sqlite3.connect(DB_PATH)) as connection:
        with connection:
            connection.execute("""
                INSERT INTO file_baselines
                (file_path, file_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    file_hash = excluded.file_hash,
                    updated_at = excluded.updated_at
            """, (file_path, file_hash, now, now))



def get_baselines():
    with closing(sqlite3.connect(DB_PATH)) as connection:
        rows = connection.execute("""
            SELECT file_path, file_hash
            FROM file_baselines
        """).fetchall()

    return {path: file_hash for path, file_hash in rows}



def remove_baseline(file_path):
    with closing(sqlite3.connect(DB_PATH)) as connection:
        with connection:
            connection.execute("""
                DELETE FROM file_baselines
                WHERE file_path = ?
            """, (file_path,))