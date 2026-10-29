
# ============================================================
# SECURITY ALERT SYSTEM
# AI-POWERED SOC DASHBOARD
# ============================================================

import sqlite3
import datetime

from flask import (
    render_template,
    request,
    jsonify,
    redirect,
    session
)


# Database location used by the existing project
SOC_DATABASE = "/tmp/soc.db"


# ------------------------------------------------------------
# SECURITY ALERTS PAGE
# ------------------------------------------------------------

@app.route("/security-alerts")
def security_alerts_page():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "security_alerts.html",
        role=session.get("role", "user")
    )


# ------------------------------------------------------------
# GET ALL SECURITY ALERTS
# ------------------------------------------------------------

@app.route("/api/security-alerts", methods=["GET"])
def get_security_alerts():

    if "user" not in session:
        return jsonify({
            "error": "Login required"
        }), 401

    conn = sqlite3.connect(SOC_DATABASE)
    conn.row_factory = sqlite3.Row

    try:

        rows = conn.execute("""
            SELECT
                a.id AS alert_id,
                l.id AS log_id,
                l.ip,
                l.country,
                l.attack,
                l.severity,
                l.risk,
                l.mitre,
                l.phase,
                l.packets,
                l.abuse,
                l.reports,
                l.time AS detected_at,
                a.status,
                a.acknowledged_by,
                a.created_at,
                a.updated_at

            FROM security_alerts AS a

            INNER JOIN logs AS l
                ON l.id = a.log_id

            ORDER BY
                CASE LOWER(COALESCE(l.severity, ''))
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END,
                a.id DESC

            LIMIT 500
        """).fetchall()

        return jsonify([
            dict(row) for row in rows
        ])

    except sqlite3.Error as error:

        app.logger.exception(
            "Unable to retrieve security alerts"
        )

        return jsonify({
            "error": "Unable to retrieve security alerts"
        }), 500

    finally:
        conn.close()


# ------------------------------------------------------------
# UPDATE ALERT STATUS
# Supported statuses:
# Open, Acknowledged, Resolved
# ------------------------------------------------------------

@app.route(
    "/api/security-alerts/<int:alert_id>",
    methods=["POST"]
)
def update_security_alert(alert_id):

    if "user" not in session:
        return jsonify({
            "error": "Login required"
        }), 401

    data = request.get_json(silent=True) or {}

    status = data.get("status")

    allowed_statuses = {
        "Open",
        "Acknowledged",
        "Resolved"
    }

    if status not in allowed_statuses:

        return jsonify({
            "error": (
                "Invalid status. Use Open, "
                "Acknowledged, or Resolved."
            )
        }), 400

    conn = sqlite3.connect(
        SOC_DATABASE,
        timeout=10
    )

    try:

        now = datetime.datetime.now().isoformat(
            timespec="seconds"
        )

        cursor = conn.execute("""
            UPDATE security_alerts

            SET
                status = ?,

                acknowledged_by = CASE
                    WHEN ? = 'Acknowledged'
                        THEN ?
                    WHEN ? = 'Open'
                        THEN NULL
                    ELSE acknowledged_by
                END,

                updated_at = ?

            WHERE id = ?
        """, (
            status,
            status,
            str(session.get("user", "analyst")),
            status,
            now,
            alert_id
        ))

        if cursor.rowcount == 0:

            conn.rollback()

            return jsonify({
                "error": "Alert not found"
            }), 404

        conn.commit()

        return jsonify({
            "success": True,
            "alert_id": alert_id,
            "status": status,
            "message": "Alert status updated successfully"
        })

    except sqlite3.Error:

        conn.rollback()

        app.logger.exception(
            "Unable to update security alert"
        )

        return jsonify({
            "error": "Unable to update alert status"
        }), 500

    finally:
        conn.close()


# ============================================================
# END SECURITY ALERT SYSTEM
# ============================================================
