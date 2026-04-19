"""
db.py – File-based storage (JSON) replacing SQLite.

Directory layout
────────────────
projects/
  index.json                   <- [{id, name, description, created_at}, ...]
  <project_name>/
    sources/                   <- source PCAPs captured by dumpcap
    forensics/                 <- tshark-extracted forensic PCAPs
    logs/
      <pcap_name>/
        eve.json               <- raw Suricata output
        fast.log
    analysis_summary.json      <- {alerts: [...], pcap_files: [...]}
    traffic_flows.json         <- [{...}, ...]
    merged_fast.log            <- all fast.log entries appended

settings.json                  <- global key/value settings
"""

import json
import os
import shutil
import threading
from collections import defaultdict
from datetime import datetime, timedelta

import config

_lock = threading.Lock()

_SETTINGS_DEFAULTS = {
    "interface":              "",
    "capture_filesize_kb":   "204800",
    "max_capture_files":     "10",
    "dedup_window_secs":     "60",
    "capture_duration_secs": "0",
    "auto_delete_clean_pcap": "0",
}


# -- file helpers ---------------------------------------------------------------

def _atomic_write(path: str, data):
    """Write JSON atomically: write to .tmp then os.replace."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _read_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


# -- init -----------------------------------------------------------------------

def init_db():
    os.makedirs(config.PROJECTS_DIR, exist_ok=True)
    if not os.path.exists(config.SETTINGS_FILE):
        _atomic_write(config.SETTINGS_FILE, _SETTINGS_DEFAULTS)


# -- settings -------------------------------------------------------------------

def get_setting(key: str, default: str = "") -> str:
    with _lock:
        data = _read_json(config.SETTINGS_FILE, {})
    v = data.get(key)
    return str(v) if v is not None else default


def set_setting(key: str, value: str):
    with _lock:
        data = _read_json(config.SETTINGS_FILE, dict(_SETTINGS_DEFAULTS))
        data[key] = value
        _atomic_write(config.SETTINGS_FILE, data)


def get_forensics_dir(project_id: int = None) -> str:
    """Return per-project forensics directory."""
    if project_id:
        p = get_project(project_id)
        if p:
            return os.path.join(config.PROJECTS_DIR, p["name"], "forensics")
    return os.path.join(config.PROJECTS_DIR, "_unassigned", "forensics")


# -- projects -------------------------------------------------------------------

def _index_path() -> str:
    return os.path.join(config.PROJECTS_DIR, "index.json")


def _load_index() -> list:
    return _read_json(_index_path(), [])


def _save_index(projects: list):
    _atomic_write(_index_path(), projects)


def create_project(name: str, description: str = "") -> int:
    name = name.strip()
    with _lock:
        projects = _load_index()
        if any(p["name"] == name for p in projects):
            raise ValueError(f"Project name '{name}' already exists")
        next_id = max((p["id"] for p in projects), default=0) + 1
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        proj = {"id": next_id, "name": name,
                "description": description.strip(), "created_at": now}
        projects.append(proj)
        _save_index(projects)

        proj_dir = os.path.join(config.PROJECTS_DIR, name)
        for sub in ("sources", "forensics", "logs"):
            os.makedirs(os.path.join(proj_dir, sub), exist_ok=True)

        _atomic_write(
            os.path.join(proj_dir, "analysis_summary.json"),
            {"id": next_id, "name": name, "created_at": now,
             "alerts": [], "pcap_files": []},
        )
        _atomic_write(os.path.join(proj_dir, "traffic_flows.json"), [])
        return next_id


def list_projects() -> list:
    with _lock:
        return list(_load_index())


def get_project(project_id: int):
    with _lock:
        projects = _load_index()
    for p in projects:
        if p["id"] == project_id:
            return p
    return None


def delete_project(project_id: int):
    with _lock:
        projects = _load_index()
        proj = next((p for p in projects if p["id"] == project_id), None)
        if not proj:
            return
        _save_index([p for p in projects if p["id"] != project_id])
        proj_dir = os.path.join(config.PROJECTS_DIR, proj["name"])
        if os.path.exists(proj_dir):
            shutil.rmtree(proj_dir)


def get_project_dir(project_id: int) -> str:
    p = get_project(project_id)
    if not p:
        return ""
    return os.path.join(config.PROJECTS_DIR, p["name"])


# -- per-project summary helpers ------------------------------------------------

def _summary_path(project_id: int) -> str:
    d = get_project_dir(project_id)
    return os.path.join(d, "analysis_summary.json") if d else ""


def _flows_path(project_id: int) -> str:
    d = get_project_dir(project_id)
    return os.path.join(d, "traffic_flows.json") if d else ""


def _load_summary(project_id: int) -> dict:
    path = _summary_path(project_id)
    if not path:
        return {"alerts": [], "pcap_files": []}
    return _read_json(path, {"alerts": [], "pcap_files": []})


def _save_summary(project_id: int, data: dict):
    path = _summary_path(project_id)
    if path:
        _atomic_write(path, data)


# -- alerts ---------------------------------------------------------------------

def upsert_alert(a: dict) -> int:
    project_id = a.get("project_id")
    if not project_id:
        return -1
    window    = int(get_setting("dedup_window_secs", "60"))
    cutoff_dt = datetime.now() - timedelta(seconds=window)
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _lock:
        summary = _load_summary(project_id)
        alerts  = summary.get("alerts", [])

        for alert in reversed(alerts):
            if (alert.get("signature_id") == a.get("signature_id")
                    and alert.get("src_ip") == a.get("src_ip")):
                try:
                    ls = datetime.strptime(alert.get("last_seen", ""),
                                           "%Y-%m-%d %H:%M:%S")
                    if ls >= cutoff_dt:
                        alert["hit_count"] = alert.get("hit_count", 1) + 1
                        alert["last_seen"] = now
                        if a.get("forensic_pcap") and not alert.get("forensic_pcap"):
                            alert["forensic_pcap"] = a["forensic_pcap"]
                        summary["alerts"] = alerts
                        _save_summary(project_id, summary)
                        return alert["id"]
                except ValueError:
                    pass

        next_id = max((al["id"] for al in alerts), default=0) + 1
        new_alert = {
            "id":            next_id,
            "project_id":    project_id,
            "timestamp":     a.get("timestamp", now),
            "src_ip":        a.get("src_ip"),
            "dst_ip":        a.get("dst_ip"),
            "src_port":      a.get("src_port"),
            "dst_port":      a.get("dst_port"),
            "proto":         a.get("proto"),
            "signature_id":  a.get("signature_id"),
            "signature":     a.get("signature"),
            "category":      a.get("category"),
            "severity":      a.get("severity"),
            "priority":      a.get("priority"),
            "source_pcap":   a.get("source_pcap"),
            "forensic_pcap": a.get("forensic_pcap"),
            "country":       a.get("country"),
            "hit_count":     1,
            "last_seen":     now,
            "created_at":    now,
        }
        alerts.append(new_alert)
        summary["alerts"] = alerts
        _save_summary(project_id, summary)
        return next_id


def update_alert_forensic(alert_id: int, forensic_filename: str,
                          project_id: int = None):
    if not project_id:
        return
    with _lock:
        summary = _load_summary(project_id)
        for alert in summary.get("alerts", []):
            if alert["id"] == alert_id:
                alert["forensic_pcap"] = forensic_filename
                break
        _save_summary(project_id, summary)


def get_alerts(page=1, per_page=50, severity=None, src_ip=None,
               hours=None, project_id=None):
    if not project_id:
        return {"total": 0, "page": page, "per_page": per_page, "items": []}
    with _lock:
        summary = _load_summary(project_id)
    alerts = list(summary.get("alerts", []))

    if severity:
        alerts = [a for a in alerts if a.get("severity") == int(severity)]
    if src_ip:
        alerts = [a for a in alerts if src_ip in (a.get("src_ip") or "")]
    if hours:
        cutoff = (datetime.now() - timedelta(hours=int(hours))).strftime(
            "%Y-%m-%d %H:%M:%S")
        alerts = [a for a in alerts if (a.get("created_at") or "") >= cutoff]

    alerts.reverse()
    total = len(alerts)
    start = (page - 1) * per_page
    return {"total": total, "page": page, "per_page": per_page,
            "items": alerts[start: start + per_page]}


def get_alert(alert_id: int, project_id: int = None):
    if not project_id:
        return None
    with _lock:
        summary = _load_summary(project_id)
    for alert in summary.get("alerts", []):
        if alert["id"] == alert_id:
            return alert
    return None


def get_dashboard_stats(project_id: int = None):
    if not project_id:
        return {"total_alerts": 0, "today_alerts": 0,
                "today_p1": 0, "today_p2": 0, "recent_alerts": []}
    today = datetime.now().strftime("%Y-%m-%d")
    with _lock:
        summary = _load_summary(project_id)
    alerts  = summary.get("alerts", [])
    total   = len(alerts)
    today_n = sum(1 for a in alerts
                  if (a.get("created_at") or "").startswith(today))
    p1      = sum(1 for a in alerts if a.get("priority") == 1
                  and (a.get("created_at") or "").startswith(today))
    p2      = sum(1 for a in alerts if a.get("priority") == 2
                  and (a.get("created_at") or "").startswith(today))
    recent  = list(reversed(alerts))[:10]
    return {"total_alerts": total, "today_alerts": today_n,
            "today_p1": p1, "today_p2": p2, "recent_alerts": recent}


def get_alert_timeseries(hours: int = 24, project_id: int = None):
    if not project_id:
        return []
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime(
        "%Y-%m-%d %H:%M:%S")
    with _lock:
        summary = _load_summary(project_id)
    alerts = [a for a in summary.get("alerts", [])
              if (a.get("created_at") or "") >= cutoff]
    hourly = defaultdict(int)
    for a in alerts:
        ts = a.get("created_at", "")
        if ts:
            hourly[ts[:13] + ":00"] += 1
    return [{"hour": k, "count": v} for k, v in sorted(hourly.items())]


def get_severity_distribution(project_id: int = None):
    if not project_id:
        return []
    with _lock:
        summary = _load_summary(project_id)
    dist = defaultdict(int)
    for a in summary.get("alerts", []):
        sev = a.get("severity")
        if sev:
            dist[sev] += 1
    return [{"severity": k, "count": v} for k, v in sorted(dist.items())]


def delete_alerts_by_source(source_pcap: str, project_id: int = None):
    if not project_id:
        return
    with _lock:
        summary = _load_summary(project_id)
        summary["alerts"] = [a for a in summary.get("alerts", [])
                              if a.get("source_pcap") != source_pcap]
        _save_summary(project_id, summary)


def get_forensic_pcaps_by_source(source_pcap: str,
                                 project_id: int = None) -> list:
    if not project_id:
        return []
    with _lock:
        summary = _load_summary(project_id)
    seen, result = set(), []
    for a in summary.get("alerts", []):
        fp = a.get("forensic_pcap")
        if fp and a.get("source_pcap") == source_pcap and fp not in seen:
            seen.add(fp)
            result.append(fp)
    return result


# -- traffic flows --------------------------------------------------------------

def insert_flows_bulk(flows: list, project_id: int = None):
    if not flows or not project_id:
        return
    path = _flows_path(project_id)
    if not path:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        existing = _read_json(path, [])
        for f in flows:
            f.setdefault("created_at", now)
        existing.extend(flows)
        _atomic_write(path, existing)


def delete_flows_by_source(source_pcap: str, project_id: int = None):
    if not project_id:
        return
    path = _flows_path(project_id)
    if not path:
        return
    with _lock:
        flows = _read_json(path, [])
        flows = [f for f in flows if f.get("source_pcap") != source_pcap]
        _atomic_write(path, flows)


def get_topn(dimension: str, n: int = 10, hours: int = 0,
             project_id: int = None):
    if not project_id:
        return []
    path = _flows_path(project_id)
    if not path:
        return []
    with _lock:
        flows = _read_json(path, [])

    if hours > 0:
        cutoff = (datetime.now() - timedelta(hours=hours)).strftime(
            "%Y-%m-%d %H:%M:%S")
        flows = [f for f in flows if (f.get("created_at") or "") >= cutoff]

    agg = defaultdict(int)
    if dimension == "bytes":
        for f in flows:
            k = f.get("src_ip")
            if k:
                agg[k] += f.get("bytes", 0)
    elif dimension in ("src_ip", "dst_ip", "proto", "country_src"):
        for f in flows:
            k = f.get(dimension)
            if k:
                agg[k] += f.get("pkts", 0)

    top = sorted(agg.items(), key=lambda x: x[1], reverse=True)[:n]
    return [{"label": k, "count": v} for k, v in top]


# -- pcap_files -----------------------------------------------------------------

def upsert_pcap(filename: str, filepath: str, filesize: int,
                alert_count: int, pcap_type: str = "source",
                project_id: int = None):
    if not project_id:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        summary = _load_summary(project_id)
        pcaps   = summary.get("pcap_files", [])
        for pcap in pcaps:
            if pcap["filename"] == filename:
                pcap["filepath"]    = filepath
                pcap["filesize"]    = filesize
                pcap["alert_count"] = alert_count
                pcap["pcap_type"]   = pcap_type
                summary["pcap_files"] = pcaps
                _save_summary(project_id, summary)
                return
        pcaps.append({
            "filename":    filename,
            "filepath":    filepath,
            "filesize":    filesize,
            "alert_count": alert_count,
            "pcap_type":   pcap_type,
            "project_id":  project_id,
            "created_at":  now,
        })
        summary["pcap_files"] = pcaps
        _save_summary(project_id, summary)


def get_pcaps(project_id: int = None):
    if not project_id:
        return []
    with _lock:
        summary = _load_summary(project_id)
    return list(reversed(summary.get("pcap_files", [])))


def delete_pcap(filename: str, project_id: int = None):
    if not project_id:
        return
    with _lock:
        summary = _load_summary(project_id)
        summary["pcap_files"] = [p for p in summary.get("pcap_files", [])
                                  if p["filename"] != filename]
        _save_summary(project_id, summary)
