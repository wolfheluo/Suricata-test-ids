"""
app.py – Flask entry point.
Run:  python app.py
URL:  http://127.0.0.1:5000
"""
import os
import subprocess
import urllib.request
import logging

from flask import (Flask, render_template, jsonify, request,
                   send_file, abort)

import config
import db
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
    for d in (config.CAPTURES_DIR, config.FORENSICS_DIR,
              config.LOGS_DIR, config.RULES_DIR):
        os.makedirs(d, exist_ok=True)
    db.init_db()
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

@app.route("/api/dashboard")
def api_dashboard():
    stats = db.get_dashboard_stats()
    status = {
        "capturing":       _watcher.is_capturing(),
        "analyzing":       _watcher.is_analyzing(),
        "interface":       _watcher.current_interface,
        "queue_size":      _watcher.queue_size(),
        "total_captured":  _watcher.get_total_captured_bytes(),
    }
    return jsonify({"stats": stats, "status": status})

@app.route("/api/traffic/live")
def api_traffic_live():
    """Return the rolling 60-second traffic history (KB/s per second)."""
    return jsonify(_watcher.get_traffic_history())

@app.route("/api/stats/timeseries")
def api_timeseries():
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_alert_timeseries(hours))

@app.route("/api/stats/severity")
def api_severity():
    return jsonify(db.get_severity_distribution())

@app.route("/api/topn")
def api_topn():
    dim   = request.args.get("dim", "src_ip")
    n     = int(request.args.get("n", 10))
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_topn(dim, n, hours))


# ══════════════════════════════════════════════════════════════════════════════
# API – alerts
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/alerts")
def api_alerts():
    return jsonify(db.get_alerts(
        page     = int(request.args.get("page", 1)),
        per_page = int(request.args.get("per_page", 50)),
        severity = request.args.get("severity"),
        src_ip   = request.args.get("src_ip"),
        hours    = request.args.get("hours"),
    ))

@app.route("/api/alerts/<int:alert_id>")
def api_alert_detail(alert_id):
    row = db.get_alert(alert_id)
    if not row:
        abort(404)
    return jsonify(dict(row))

@app.route("/api/alerts/<int:alert_id>/preview")
def api_alert_preview(alert_id):
    row = db.get_alert(alert_id)
    if not row or not row["forensic_pcap"]:
        return jsonify({"packets": ""})
    path = os.path.join(config.FORENSICS_DIR, row["forensic_pcap"])
    if not os.path.exists(path):
        return jsonify({"packets": ""})
    r = subprocess.run(
        [config.TSHARK_BIN, "-r", path],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
    )
    return jsonify({"packets": r.stdout[:30_000]})

@app.route("/api/alerts/<int:alert_id>/hexdump")
def api_alert_hexdump(alert_id):
    row = db.get_alert(alert_id)
    if not row or not row["forensic_pcap"]:
        return jsonify({"hexdump": ""})
    path = os.path.join(config.FORENSICS_DIR, row["forensic_pcap"])
    if not os.path.exists(path):
        return jsonify({"hexdump": ""})
    r = subprocess.run(
        [config.TSHARK_BIN, "-r", path, "-x"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
    )
    return jsonify({"hexdump": r.stdout[:50_000]})

@app.route("/api/alerts/<int:alert_id>/download")
def api_alert_download(alert_id):
    row = db.get_alert(alert_id)
    if not row or not row["forensic_pcap"]:
        abort(404)
    path = os.path.join(config.FORENSICS_DIR, row["forensic_pcap"])
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True,
                     download_name=row["forensic_pcap"])


# ══════════════════════════════════════════════════════════════════════════════
# API – PCAP library
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/pcap")
def api_pcap_list():
    return jsonify(db.get_pcaps())

@app.route("/api/pcap/<filename>/download")
def api_pcap_download(filename):
    safe = os.path.basename(filename)          # prevent path traversal
    path = os.path.join(config.FORENSICS_DIR, safe)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=safe)

@app.route("/api/pcap/<filename>/preview")
def api_pcap_preview(filename):
    safe = os.path.basename(filename)
    path = os.path.join(config.FORENSICS_DIR, safe)
    if not os.path.exists(path):
        abort(404)
    r = subprocess.run(
        [config.TSHARK_BIN, "-r", path],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
    )
    return jsonify({"packets": r.stdout[:30_000]})

@app.route("/api/pcap/<filename>", methods=["DELETE"])
def api_pcap_delete(filename):
    safe = os.path.basename(filename)
    path = os.path.join(config.FORENSICS_DIR, safe)
    if os.path.exists(path):
        os.remove(path)
    db.delete_pcap(safe)
    return jsonify({"ok": True})

@app.route("/api/pcap/batch_delete", methods=["POST"])
def api_pcap_batch_delete():
    filenames = request.json.get("filenames", [])
    for filename in filenames:
        safe = os.path.basename(filename)
        path = os.path.join(config.FORENSICS_DIR, safe)
        if os.path.exists(path):
            os.remove(path)
        db.delete_pcap(safe)
    return jsonify({"ok": True, "deleted": len(filenames)})


# ══════════════════════════════════════════════════════════════════════════════
# API – capture control
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    data      = request.json or {}
    interface = data.get("interface") or db.get_setting("interface", "")
    if not interface:
        return jsonify({"error": "No interface specified"}), 400
    filesize_kb  = int(db.get_setting("capture_filesize_kb",
                                      str(config.DEFAULT_CAPTURE_FILESIZE_KB)))
    duration_secs = int(db.get_setting("capture_duration_secs", "0"))
    db.set_setting("interface", interface)
    _watcher.start_capture(interface, filesize_kb, duration_secs)
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
    "dedup_window_secs", "capture_duration_secs",
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
