"""
analyzer.py – Runs Suricata in offline mode, checks fast.log for Priority 1/2,
              extracts forensic PCAPs via tshark, stores results in SQLite.
"""
import os
import json
import shutil
import subprocess
import logging
from datetime import datetime

import config
import db
import geoip_service

log = logging.getLogger("analyzer")


# ── Suricata runner ──────────────────────────────────────────────────────────

def analyze_pcap(pcap_path: str) -> bool:
    """
    Analyze *pcap_path* with Suricata.

    Returns True  → high-priority alerts found (Priority 1 or 2).
    Returns False → no high-priority alerts.
    The source PCAP is always saved to the PCAP library after analysis.
    """
    pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]
    log_dir   = os.path.join(config.LOGS_DIR, pcap_name)
    os.makedirs(log_dir, exist_ok=True)

    cmd = [config.SURICATA_BIN, "-r", pcap_path, "-l", log_dir, "-k", "none"]

    # Append custom rules file if available
    rules_file = os.path.join(config.RULES_DIR, "emerging-all.rules")
    if os.path.exists(rules_file):
        cmd += ["-S", rules_file]

    log.info("Running: %s", " ".join(cmd))

    # On Windows, Suricata's bundled DLLs and Npcap's wpcap.dll must be
    # resolvable.  We prepend both directories to PATH and set cwd to the
    # Suricata installation folder so the loader finds them.
    env = os.environ.copy()
    extra = os.pathsep.join(filter(None, [
        config.SURICATA_DIR,
        config.NPCAP_DIR if os.path.isdir(config.NPCAP_DIR) else "",
    ]))
    env["PATH"] = extra + os.pathsep + env.get("PATH", "")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, check=False,
            cwd=config.SURICATA_DIR, env=env,
        )
        if result.returncode != 0:
            log.warning("Suricata exited with code %d. stderr: %s",
                        result.returncode, result.stderr[:500])
    except subprocess.TimeoutExpired:
        log.error("Suricata timed out on %s", pcap_path)
        return False
    except FileNotFoundError:
        log.error("Suricata binary not found: %s", config.SURICATA_BIN)
        return False

    fast_log = os.path.join(log_dir, "fast.log")
    eve_log  = os.path.join(log_dir, "eve.json")

    has_high = _check_high_priority(fast_log)

    if not has_high:
        auto_delete = db.get_setting("auto_delete_clean_pcap", "0") == "1"
        if auto_delete:
            log.info("No Priority 1/2 alerts in %s – auto-delete enabled, removing.", pcap_name)
            _safe_remove(pcap_path)
        else:
            log.info("No Priority 1/2 alerts in %s – saving to PCAP library.", pcap_name)
            _save_source_pcap_to_library(pcap_path, alert_count=0)
        return False

    # Parse eve.json, store alerts, extract forensics
    alerts = _parse_eve_json(eve_log)
    log.info("%d alerts found in %s", len(alerts), pcap_name)
    for alert in alerts:
        _process_alert(alert, pcap_path)

    # Save the source PCAP to the library now that forensic extraction is complete
    _save_source_pcap_to_library(pcap_path, alert_count=len(alerts))

    return True


# ── fast.log priority check ─────────────────────────────────────────────────

def _check_high_priority(fast_log_path: str) -> bool:
    if not os.path.exists(fast_log_path):
        return False
    try:
        with open(fast_log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "Priority: 1" in line or "Priority: 2" in line:
                    return True
    except OSError:
        pass
    return False


# ── eve.json parser ──────────────────────────────────────────────────────────

def _parse_eve_json(eve_path: str) -> list:
    alerts = []
    if not os.path.exists(eve_path):
        return alerts
    try:
        with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return alerts


# ── per-alert processing ─────────────────────────────────────────────────────

def _process_alert(event: dict, source_pcap: str):
    alert_obj = event.get("alert", {})
    priority  = alert_obj.get("severity", 3)      # eve.json uses "severity" field
    src_ip    = event.get("src_ip", "")
    dst_ip    = event.get("dest_ip", "")

    # Only extract forensics for Priority 1 or 2
    if priority not in (1, 2):
        _store_alert(event, source_pcap, forensic_pcap=None)
        return

    forensic_path = _extract_forensic(event, source_pcap)
    forensic_name = os.path.basename(forensic_path) if forensic_path else None

    alert_id = _store_alert(event, source_pcap, forensic_pcap=forensic_name)

    if forensic_path and os.path.exists(forensic_path):
        size = os.path.getsize(forensic_path)
        db.upsert_pcap(forensic_name, forensic_path, size, 1)


def _store_alert(event: dict, source_pcap: str, forensic_pcap) -> int:
    alert_obj = event.get("alert", {})
    src_ip    = event.get("src_ip", "")
    return db.upsert_alert({
        "timestamp":    event.get("timestamp", datetime.now().isoformat()),
        "src_ip":       src_ip,
        "dst_ip":       event.get("dest_ip"),
        "src_port":     event.get("src_port"),
        "dst_port":     event.get("dest_port"),
        "proto":        event.get("proto"),
        "signature_id": alert_obj.get("signature_id"),
        "signature":    alert_obj.get("signature"),
        "category":     alert_obj.get("category"),
        "severity":     alert_obj.get("severity", 3),
        "priority":     alert_obj.get("severity", 3),
        "source_pcap":  os.path.basename(source_pcap),
        "forensic_pcap": forensic_pcap,
        "country":      geoip_service.lookup(src_ip),
    })


# ── tshark forensic extraction ───────────────────────────────────────────────

def _extract_forensic(event: dict, source_pcap: str):
    src_ip   = event.get("src_ip", "")
    dst_ip   = event.get("dest_ip", "")
    src_port = event.get("src_port")
    dst_port = event.get("dest_port")
    proto    = (event.get("proto") or "").lower()
    sig_id   = event.get("alert", {}).get("signature_id", 0)
    ts       = event.get("timestamp", datetime.now().isoformat())

    # Build display filter (5-tuple conversation)
    if proto in ("tcp", "udp") and src_port and dst_port:
        fwd = f"(ip.src=={src_ip} && ip.dst=={dst_ip} && {proto}.srcport=={src_port} && {proto}.dstport=={dst_port})"
        rev = f"(ip.src=={dst_ip} && ip.dst=={src_ip} && {proto}.srcport=={dst_port} && {proto}.dstport=={src_port})"
        display_filter = f"{fwd} || {rev}"
    else:
        display_filter = f"ip.addr=={src_ip} && ip.addr=={dst_ip}"

    ts_clean  = ts[:19].replace(":", "").replace("T", "_").replace("-", "")
    src_clean = src_ip.replace(".", "_")
    out_name  = f"{ts_clean}_{src_clean}_{sig_id}.pcap"
    out_path  = os.path.join(config.FORENSICS_DIR, out_name)

    cmd = [
        config.TSHARK_BIN, "-r", source_pcap,
        "-Y", display_filter,
        "-w", out_path,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=120, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error("tshark failed: %s", e)
        return None

    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        log.info("Forensic PCAP saved: %s", out_name)
        return out_path
    return None


# ── helpers ──────────────────────────────────────────────────────────────────

def _save_source_pcap_to_library(pcap_path: str, alert_count: int):
    """Move the source PCAP to forensics/ and register it in the PCAP library."""
    basename  = os.path.basename(pcap_path)
    dest_path = os.path.join(config.FORENSICS_DIR, basename)
    try:
        if pcap_path != dest_path:
            shutil.move(pcap_path, dest_path)
        size = os.path.getsize(dest_path)
        db.upsert_pcap(basename, dest_path, size, alert_count)
        log.info("Source PCAP saved to library: %s (%d bytes, %d alerts)",
                 basename, size, alert_count)
    except OSError as e:
        log.error("Failed to save source PCAP to library (%s): %s", basename, e)


def _safe_remove(path: str):
    try:
        os.remove(path)
    except OSError as e:
        log.warning("Could not delete %s: %s", path, e)
