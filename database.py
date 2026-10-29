
import sqlite3
from datetime import datetime

DB_NAME = "/tmp/soc.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- INIT DATABASE ----------------

def init_db():
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        country TEXT,
        packets INTEGER,
        login_fail INTEGER,
        sql INTEGER,
        attack TEXT,
        severity TEXT,
        risk INTEGER,
        mitre TEXT,
        abuse INTEGER,
        reports INTEGER,
        attack_prob INTEGER,
        phase TEXT,
        time TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack TEXT,
        severity TEXT,
        risk INTEGER,
        phase TEXT,
        status TEXT DEFAULT 'Open',
        analyst TEXT,
        comment TEXT,
        time TEXT,
        closed_time TEXT
    )
    """)

    # New table for alert-management status.
    # Original attack records in logs are not modified when alerts are resolved.
    c.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id INTEGER NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'Open'
            CHECK(status IN ('Open', 'Acknowledged', 'Resolved')),
        acknowledged_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(log_id) REFERENCES logs(id)
    )
    """)

    # Create alerts for existing non-normal attack records.
    c.execute("""
    INSERT OR IGNORE INTO security_alerts
        (log_id, status, created_at, updated_at)
    SELECT id, 'Open',
           COALESCE(time, datetime('now')),
           COALESCE(time, datetime('now'))
    FROM logs
    WHERE attack IS NOT NULL
      AND LOWER(attack) != 'normal'
    """)

    conn.commit()
    conn.close()


# ---------------- INSERT ATTACK ----------------

def insert_attack(
    ip, country, packets, login_fail, sql,
    attack, severity, risk, mitre,
    abuse, reports, attack_prob, phase
):
    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().isoformat(timespec="seconds")

    cursor.execute("""
    INSERT INTO logs(
        ip, country, packets, login_fail, sql,
        attack, severity, risk, mitre,
        abuse, reports, attack_prob, phase, time
    )
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        ip, country, packets, login_fail, sql,
        attack, severity, risk, mitre,
        abuse, reports, attack_prob, phase, now
    ))

    log_id = cursor.lastrowid

    # Normal events remain in logs but are not raised as security alerts.
    if attack and attack.strip().lower() != "normal":
        cursor.execute("""
        INSERT INTO security_alerts
            (log_id, status, created_at, updated_at)
        VALUES (?, 'Open', ?, ?)
        """, (log_id, now, now))

    conn.commit()
    conn.close()


# ---------------- FETCH LOGS ----------------

def fetch_logs():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cursor.fetchall()

    conn.close()
    return [tuple(row) for row in rows]


# ---------------- CREATE INCIDENT ----------------

def create_incident(attack, severity, risk, phase):
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    INSERT INTO incidents(attack, severity, risk, phase, time)
    VALUES(?,?,?,?,datetime('now'))
    """, (attack, severity, risk, phase))

    conn.commit()
    conn.close()


# ---------------- SAVE BLOCKED IP ----------------

def save_block(ip):
    conn = get_connection()
    cursor = conn.cursor()

    # Create the table if an older database doesn't have it.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        time TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("INSERT INTO blocked_ips(ip) VALUES(?)", (ip,))

    conn.commit()
    conn.close()
