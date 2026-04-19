"""
app.py – Flask entry point.
Run:  python app.py
URL:  http://0.0.0.0:5000
"""
import os
import subprocess
import threading
import urllib.request
import logging

from flask import (Flask, render_template, jsonify, request,
                   send_file, abort)

import config
import db
import analyzer
import geoip_service
from watcher import CaptureWatcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)

app    = Flask(__name__)
app.secret_key = config.SECRET_KEY
_watcher = CaptureWatcher()


def _startup():
    for d in (config.CAPTURES_DIR, config.RULES_DIR, config.PROJECTS_DIR):
        os.makedirs(d, exist_ok=True)
    db.init_db()                               # must come first – creates settings.json
    geoip_service.init_geoip()
    _watcher.start()


# ══════════════════════════════════════════════════════════════════════════════
# Page routes
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/events")
def events():
    return render_template("events.html")

@app.route("/pcap")
def pcap_library():
    return render_template("pcap_library.html")

@app.route("/settings")
def settings():
    return render_template("settings.html")


# ══════════════════════════════════════════════════════════════════════════════
# API – dashboard / stats
# ══════════════════════════════════════════════════════════════════════════════

def _current_pid():
    """Return active project_id (int) or None."""
    return _watcher.current_project_id


@app.route("/api/dashboard")
def api_dashboard():
    pid   = _current_pid()
    stats = db.get_dashboard_stats(project_id=pid)
    current_project = db.get_project(pid) if pid else None
    status = {
        "capturing":       _watcher.is_capturing(),
        "analyzing":       _watcher.is_analyzing(),
        "interface":       _watcher.current_interface,
        "queue_size":      _watcher.queue_size(),
        "total_captured":  _watcher.get_total_captured_bytes(),
        "current_project": current_project,
    }
    return jsonify({"stats": stats, "status": status})

@app.route("/api/traffic/live")
def api_traffic_live():
    """Return the rolling 60-second traffic history (KB/s per second)."""
    return jsonify(_watcher.get_traffic_history())

@app.route("/api/stats/timeseries")
def api_timeseries():
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_alert_timeseries(hours, project_id=_current_pid()))

@app.route("/api/stats/severity")
def api_severity():
    return jsonify(db.get_severity_distribution(project_id=_current_pid()))

@app.route("/api/topn")
def api_topn():
    dim   = request.args.get("dim", "src_ip")
    n     = int(request.args.get("n", 10))
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_topn(dim, n, hours, project_id=_current_pid()))


# ══════════════════════════════════════════════════════════════════════════════
# API – alerts
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/alerts")
def api_alerts():
    return jsonify(db.get_alerts(
        page       = int(request.args.get("page", 1)),
        per_page   = int(request.args.get("per_page", 50)),
        severity   = request.args.get("severity"),
        src_ip     = request.args.get("src_ip"),
        hours      = request.args.get("hours"),
        project_id = _current_pid(),
    ))

@app.route("/api/alerts/<int:alert_id>")
def api_alert_detail(alert_id):
    row = db.get_alert(alert_id, project_id=_current_pid())
    if not row:
        abort(404)
    return jsonify(row)

@app.route("/api/alerts/<int:alert_id>/preview")
def api_alert_preview(alert_id):
    pid = _current_pid()
    row = db.get_alert(alert_id, project_id=pid)
    if not row or not row.get("forensic_pcap"):
        return jsonify({"packets": ""})
    path = os.path.join(db.get_forensics_dir(pid), row["forensic_pcap"])
    if not os.path.exists(path):
        return jsonify({"packets": ""})
    r = subprocess.run(
        [config.TSHARK_BIN, "-r", path],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
    )
    return jsonify({"packets": r.stdout[:30_000]})

@app.route("/api/alerts/<int:alert_id>/hexdump")
def api_alert_hexdump(alert_id):
    pid = _current_pid()
    row = db.get_alert(alert_id, project_id=pid)
    if not row or not row.get("forensic_pcap"):
        return jsonify({"hexdump": ""})
    path = os.path.join(db.get_forensics_dir(pid), row["forensic_pcap"])
    if not os.path.exists(path):
        return jsonify({"hexdump": ""})
    r = subprocess.run(
        [config.TSHARK_BIN, "-r", path, "-x"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
    )
    return jsonify({"hexdump": r.stdout[:50_000]})

@app.route("/api/alerts/<int:alert_id>/download")
def api_alert_download(alert_id):
    pid = _current_pid()
    row = db.get_alert(alert_id, project_id=pid)
    if not row or not row.get("forensic_pcap"):
        abort(404)
    path = os.path.join(db.get_forensics_dir(pid), row["forensic_pcap"])
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True,
                     download_name=row["forensic_pcap"])


# ══════════════════════════════════════════════════════════════════════════════
# API – PCAP library
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/pcap")
def api_pcap_list():
    return jsonify(db.get_pcaps(project_id=_current_pid()))


def _pcap_path(filename: str, project_id) -> str:
    """Resolve PCAP filename to an absolute path within the project dirs."""
    safe = os.path.basename(filename)
    if project_id:
        proj_dir = db.get_project_dir(project_id)
        # Check sources/ first, then forensics/
        for sub in ("forensics", "sources"):
            p = os.path.join(proj_dir, sub, safe)
            if os.path.exists(p):
                return p
    return ""


@app.route("/api/pcap/<filename>/download")
def api_pcap_download(filename):
    path = _pcap_path(filename, _current_pid())
    if not path:
        abort(404)
    return send_file(path, as_attachment=True,
                     download_name=os.path.basename(filename))

@app.route("/api/pcap/<filename>/preview")
def api_pcap_preview(filename):
    path = _pcap_path(filename, _current_pid())
    if not path:
        abort(404)
    r = subprocess.run(
        [config.TSHARK_BIN, "-r", path],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
    )
    return jsonify({"packets": r.stdout[:30_000]})

@app.route("/api/pcap/<filename>", methods=["DELETE"])
def api_pcap_delete(filename):
    pid  = _current_pid()
    safe = os.path.basename(filename)
    path = _pcap_path(safe, pid)
    if path and os.path.exists(path):
        os.remove(path)
    db.delete_pcap(safe, project_id=pid)
    return jsonify({"ok": True})

@app.route("/api/pcap/<filename>/reanalyze", methods=["POST"])
def api_pcap_reanalyze(filename):
    pid  = _current_pid()
    safe = os.path.basename(filename)
    path = _pcap_path(safe, pid)
    if not path:
        abort(404)
    def _run():
        analyzer.reanalyze_pcap(path, project_id=pid)
    threading.Thread(target=_run, daemon=True, name=f"reanalyze-{safe}").start()
    return jsonify({"queued": True})

@app.route("/api/pcap/batch_delete", methods=["POST"])
def api_pcap_batch_delete():
    pid       = _current_pid()
    filenames = request.json.get("filenames", [])
    for filename in filenames:
        safe = os.path.basename(filename)
        path = _pcap_path(safe, pid)
        if path and os.path.exists(path):
            os.remove(path)
        db.delete_pcap(safe, project_id=pid)
    return jsonify({"ok": True, "deleted": len(filenames)})


# ══════════════════════════════════════════════════════════════════════════════
# API – capture control
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    data       = request.json or {}
    interface  = data.get("interface") or db.get_setting("interface", "")
    project_id = data.get("project_id")
    if not project_id:
        return jsonify({"error": "請先選擇或建立一個專案"}), 400
    project = db.get_project(int(project_id))
    if not project:
        return jsonify({"error": "找不到指定的專案"}), 404
    if not interface:
        return jsonify({"error": "No interface specified"}), 400
    filesize_kb  = int(db.get_setting("capture_filesize_kb",
                                      str(config.DEFAULT_CAPTURE_FILESIZE_KB)))
    duration_secs = int(db.get_setting("capture_duration_secs", "0"))
    exclude_ips   = data.get("exclude_ips", [])
    db.set_setting("interface", interface)
    _watcher.set_project(int(project_id))
    _watcher.start_capture(interface, filesize_kb, duration_secs, exclude_ips)
    return jsonify({"ok": True})

@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    _watcher.stop_capture()
    return jsonify({"ok": True})

@app.route("/api/interfaces")
def api_interfaces():
    try:
        r = subprocess.run(
            [config.DUMPCAP_BIN, "-D"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
        )
        interfaces = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(". ", 1)
            if len(parts) == 2:
                interfaces.append({"index": parts[0], "name": parts[1]})
        return jsonify(interfaces)
    except FileNotFoundError:
        return jsonify({"error": f"dumpcap not found at {config.DUMPCAP_BIN}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# API – settings
# ══════════════════════════════════════════════════════════════════════════════

_SETTING_KEYS = [
    "interface", "capture_filesize_kb", "max_capture_files",
    "dedup_window_secs", "capture_duration_secs", "auto_delete_clean_pcap",
]

@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify({k: db.get_setting(k, "") for k in _SETTING_KEYS})

@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    data = request.json or {}
    for k, v in data.items():
        if k in _SETTING_KEYS:
            db.set_setting(k, str(v))
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════════════
# API – projects
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/projects", methods=["GET"])
def api_projects_list():
    return jsonify(db.list_projects())

@app.route("/api/projects", methods=["POST"])
def api_projects_create():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "專案名稱不能為空"}), 400
    description = (data.get("description") or "").strip()
    try:
        project_id = db.create_project(name, description)
    except Exception as e:
        return jsonify({"error": f"專案名稱已存在或發生錯誤：{e}"}), 409
    project = db.get_project(project_id)
    return jsonify(project), 201

@app.route("/api/projects/<int:project_id>", methods=["GET"])
def api_projects_get(project_id):
    project = db.get_project(project_id)
    if not project:
        abort(404)
    return jsonify(project)

@app.route("/api/projects/<int:project_id>", methods=["DELETE"])
def api_projects_delete(project_id):
    if _watcher.current_project_id == project_id:
        return jsonify({"error": "無法刪除目前使用中的專案，請先切換專案後再刪除"}), 400
    db.delete_project(project_id)
    return jsonify({"ok": True})

@app.route("/api/projects/current", methods=["GET"])
def api_projects_current_get():
    if _watcher.current_project_id:
        project = db.get_project(_watcher.current_project_id)
        return jsonify(project or {})
    return jsonify({})

@app.route("/api/projects/current", methods=["POST"])
def api_projects_current_set():
    data = request.json or {}
    project_id = data.get("project_id")
    if project_id is None:
        _watcher.set_project(None)
        return jsonify({"ok": True})
    project = db.get_project(int(project_id))
    if not project:
        return jsonify({"error": "找不到指定的專案"}), 404
    _watcher.set_project(int(project_id))
    return jsonify({"ok": True, "project": project})


# ══════════════════════════════════════════════════════════════════════════════
# API – rules
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/rules")
def api_rules_list():
    rules_file = os.path.join(config.RULES_DIR, "emerging-all.rules")
    if not os.path.exists(rules_file):
        return jsonify({"rules": [], "total": 0, "page": 1})
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 100))
    rules    = []
    with open(rules_file, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            line = line.rstrip()
            if not line:
                continue
            enabled = not line.startswith("#")
            rules.append({"lineno": i + 1, "text": line, "enabled": enabled})
    start = (page - 1) * per_page
    return jsonify({
        "rules":    rules[start:start + per_page],
        "total":    len(rules),
        "page":     page,
        "per_page": per_page,
    })

@app.route("/api/rules/upload", methods=["POST"])
def api_rules_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename.endswith(".rules"):
        return jsonify({"error": "File must have .rules extension"}), 400
    safe_name = os.path.basename(f.filename)
    dest = os.path.join(config.RULES_DIR, safe_name)
    f.save(dest)
    return jsonify({"ok": True, "filename": safe_name})

@app.route("/api/rules/update", methods=["POST"])
def api_rules_update():
    """Download latest Emerging Threats rules (requires internet)."""
    url  = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules"
    dest = os.path.join(config.RULES_DIR, "emerging-all.rules")
    try:
        urllib.request.urlretrieve(url, dest)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    _startup()
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT,
            debug=False, use_reloader=False)
