"""
db.py – SQLite helper (thread-safe via check_same_thread=False + a module lock).
"""
import sqlite3
import threading
from datetime import datetime, timedelta
import config

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT    NOT NULL,
    src_ip         TEXT,
    dst_ip         TEXT,
    src_port       INTEGER,
    dst_port       INTEGER,
    proto          TEXT,
    signature_id   INTEGER,
    signature      TEXT,
    category       TEXT,
    severity       INTEGER,
    priority       INTEGER,
    source_pcap    TEXT,
    forensic_pcap  TEXT,
    country        TEXT,
    hit_count      INTEGER DEFAULT 1,
    last_seen      TEXT,
    created_at     TEXT    DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS pcap_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT    NOT NULL UNIQUE,
    filepath    TEXT    NOT NULL,
    filesize    INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    created_at  TEXT    DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings VALUES ('interface',              '');
INSERT OR IGNORE INTO settings VALUES ('capture_filesize_kb',   '204800');
INSERT OR IGNORE INTO settings VALUES ('max_capture_files',     '10');
INSERT OR IGNORE INTO settings VALUES ('dedup_window_secs',     '60');
INSERT OR IGNORE INTO settings VALUES ('capture_duration_secs', '0');
INSERT OR IGNORE INTO settings VALUES ('auto_delete_clean_pcap', '0');
"""


def _conn():
    c = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    with _lock, _conn() as c:
        c.executescript(SCHEMA)


# ── settings ──────────────────────────────────────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    with _lock, _conn() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))


# ── alerts ─────────────────────────────────────────────────────────────────

def upsert_alert(a: dict) -> int:
    """Insert a new alert or increment hit_count if duplicate within dedup window."""
    window = int(get_setting("dedup_window_secs", "60"))
    cutoff = (datetime.now() - timedelta(seconds=window)).strftime("%Y-%m-%d %H:%M:%S")
    with _lock, _conn() as c:
        row = c.execute(
            """SELECT id FROM alerts
               WHERE signature_id=? AND src_ip=? AND last_seen >= ?
               ORDER BY id DESC LIMIT 1""",
            (a.get("signature_id"), a.get("src_ip"), cutoff),
        ).fetchone()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if row:
            c.execute(
                "UPDATE alerts SET hit_count=hit_count+1, last_seen=? WHERE id=?",
                (now, row["id"]),
            )
            return row["id"]
        c.execute(
            """INSERT INTO alerts
               (timestamp,src_ip,dst_ip,src_port,dst_port,proto,
                signature_id,signature,category,severity,priority,
                source_pcap,forensic_pcap,country,last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                a.get("timestamp", now), a.get("src_ip"), a.get("dst_ip"),
                a.get("src_port"), a.get("dst_port"), a.get("proto"),
                a.get("signature_id"), a.get("signature"), a.get("category"),
                a.get("severity"), a.get("priority"),
                a.get("source_pcap"), a.get("forensic_pcap"), a.get("country"), now,
            ),
        )
        return c.lastrowid


def update_alert_forensic(alert_id: int, forensic_filename: str):
    with _lock, _conn() as c:
        c.execute(
            "UPDATE alerts SET forensic_pcap=? WHERE id=?",
            (forensic_filename, alert_id),
        )


def get_alerts(page=1, per_page=50, severity=None, src_ip=None, hours=None):
    clauses, params = [], []
    if severity:
        clauses.append("severity=?"); params.append(int(severity))
    if src_ip:
        clauses.append("src_ip LIKE ?"); params.append(f"%{src_ip}%")
    if hours:
        cutoff = (datetime.now() - timedelta(hours=int(hours))).strftime("%Y-%m-%d %H:%M:%S")
        clauses.append("created_at >= ?"); params.append(cutoff)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with _lock, _conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]
        rows  = c.execute(
            f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page],
        ).fetchall()
    return {"total": total, "page": page, "per_page": per_page,
            "items": [dict(r) for r in rows]}


def get_alert(alert_id: int):
    with _lock, _conn() as c:
        return c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()


def get_dashboard_stats():
    today = datetime.now().strftime("%Y-%m-%d")
    with _lock, _conn() as c:
        total   = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        today_n = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= ?", (today,)
        ).fetchone()[0]
        p1      = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE priority=1 AND created_at >= ?", (today,)
        ).fetchone()[0]
        p2      = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE priority=2 AND created_at >= ?", (today,)
        ).fetchone()[0]
        recent  = c.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 10"
        ).fetchall()
    return {
        "total_alerts":  total,
        "today_alerts":  today_n,
        "today_p1":      p1,
        "today_p2":      p2,
        "recent_alerts": [dict(r) for r in recent],
    }


def get_alert_timeseries(hours: int = 24):
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    with _lock, _conn() as c:
        rows = c.execute(
            """SELECT strftime('%Y-%m-%d %H:00', created_at) AS hour,
                      COUNT(*) AS count
               FROM alerts WHERE created_at >= ?
               GROUP BY hour ORDER BY hour""",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_severity_distribution():
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
        ).fetchall()
    return [dict(r) for r in rows]


def get_topn(dimension: str, n: int = 10, hours: int = 24):
    allowed = {"src_ip", "dst_ip", "dst_port", "signature_id", "country"}
    if dimension not in allowed:
        return []
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    with _lock, _conn() as c:
        rows = c.execute(
            f"""SELECT {dimension} AS label, SUM(hit_count) AS count
                FROM alerts WHERE created_at >= ? AND {dimension} IS NOT NULL
                GROUP BY {dimension} ORDER BY count DESC LIMIT ?""",
            (cutoff, n),
        ).fetchall()
    return [dict(r) for r in rows]


# ── pcap_files ─────────────────────────────────────────────────────────────

def upsert_pcap(filename: str, filepath: str, filesize: int, alert_count: int):
    with _lock, _conn() as c:
        c.execute(
            """INSERT OR REPLACE INTO pcap_files (filename,filepath,filesize,alert_count)
               VALUES (?,?,?,?)""",
            (filename, filepath, filesize, alert_count),
        )


def get_pcaps():
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM pcap_files ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_pcap(filename: str):
    with _lock, _conn() as c:
        c.execute("DELETE FROM pcap_files WHERE filename=?", (filename,))


def delete_alerts_by_source(source_pcap: str):
    """Delete all alerts whose source_pcap matches *source_pcap* (basename)."""
    with _lock, _conn() as c:
        c.execute("DELETE FROM alerts WHERE source_pcap=?", (source_pcap,))
