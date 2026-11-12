
import sqlite3
import csv
import io
import os
from contextlib import closing

from flask import Flask, render_template, send_file, request

from core.integrity import calculate_hash
from core.alerts import get_baselines, save_baseline
from core.scanner import scan_files

app = Flask(__name__)

DB_PATH = "database/security.db"
MONITOR_FOLDER = "monitored_files"


@app.route("/")
def dashboard():

    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip()
    event_type = request.args.get("event_type", "").strip()

    try:
        with closing(sqlite3.connect(DB_PATH)) as connection:
            connection.row_factory = sqlite3.Row

            query = "SELECT * FROM security_events WHERE 1=1"
            parameters = []

            if search:
                query += " AND file_path LIKE ?"
                parameters.append(f"%{search}%")

            if severity:
                query += " AND severity = ?"
                parameters.append(severity)

            if event_type:
                query += " AND event_type = ?"
                parameters.append(event_type)

            query += " ORDER BY id DESC LIMIT 100"

            events = connection.execute(
                query, parameters
            ).fetchall()

            total_events = connection.execute("""
                SELECT COUNT(*) FROM security_events
            """).fetchone()[0]

            created = connection.execute("""
                SELECT COUNT(*) FROM security_events
                WHERE event_type = 'FILE_CREATED'
            """).fetchone()[0]

            modified = connection.execute("""
                SELECT COUNT(*) FROM security_events
                WHERE event_type IN (
                    'FILE_MODIFIED',
                    'INTEGRITY_VIOLATION'
                )
            """).fetchone()[0]

            deleted = connection.execute("""
                SELECT COUNT(*) FROM security_events
                WHERE event_type = 'FILE_DELETED'
            """).fetchone()[0]

    except sqlite3.Error:
        return "Database error. Please try again.", 500

    return render_template(
        "index.html",
        events=events,
        total_events=total_events,
        created=created,
        modified=modified,
        deleted=deleted,
        search=search,
        severity=severity,
        event_type=event_type
    )


@app.route("/scan", methods=["POST"])
def run_scan():

    try:
        scan_results = scan_files()

    except (sqlite3.Error, OSError):
        return "Unable to complete the security scan.", 500

    return render_template(
        "scan_results.html",
        results=scan_results,
        total=len(scan_results)
    )


@app.route("/export")
def export_report():

    try:
        with closing(sqlite3.connect(DB_PATH)) as connection:
            events = connection.execute("""
                SELECT id, file_path, event_type, event_time, severity
                FROM security_events
                ORDER BY id DESC
            """).fetchall()

    except sqlite3.Error:
        return "Unable to export the security report.", 500

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Event ID",
        "File Path",
        "Event Type",
        "Event Time",
        "Severity"
    ])

    writer.writerows(events)

    csv_data = io.BytesIO(output.getvalue().encode("utf-8"))
    output.close()

    return send_file(
        csv_data,
        mimetype="text/csv",
        as_attachment=True,
        download_name="SentinelFIM_Security_Report.csv"
    )


@app.route("/approve", methods=["POST"])
def approve_file():

    file_path = request.form.get("file_path", "").strip()

    if not file_path:
        return "No file selected.", 400

    monitor_root = os.path.normcase(
        os.path.realpath(MONITOR_FOLDER)
    )

    absolute_path = os.path.abspath(file_path)

    if os.path.islink(absolute_path):
        return "Symbolic links cannot be approved.", 403

    absolute_path = os.path.normcase(
        os.path.realpath(absolute_path)
    )

    try:
        if os.path.commonpath(
            [monitor_root, absolute_path]
        ) != monitor_root:
            return "Invalid file path.", 403

    except ValueError:
        return "Invalid file path.", 403

    if not os.path.isfile(absolute_path):
        return "File not found.", 404

    try:
        trusted_baselines = get_baselines()

        if file_path in trusted_baselines:
            return "This file is already registered as trusted.", 400

        current_hash = calculate_hash(absolute_path)

        if current_hash is None:
            return "Could not calculate file hash.", 400

        save_baseline(file_path, current_hash)

        scan_results = scan_files()

    except (sqlite3.Error, OSError):
        return "Unable to approve the file. Please try again.", 500

    return render_template(
        "scan_results.html",
        results=scan_results,
        total=len(scan_results)
    )


if __name__ == "__main__":
    app.run(debug=True)
