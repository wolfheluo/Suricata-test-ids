"""
analyzer.py - Runs Suricata offline, stores results in per-project folders.

Project layout written by this module:
  projects/<name>/
    logs/<pcap_name>/eve.json   (Suricata raw output, copied here)
    logs/<pcap_name>/fast.log
    sources/<pcap>.pcap         (original captured PCAP)
    forensics/<ts>_<ip>_<sid>.pcap
    analysis_summary.json       (alerts + pcap_files index)
    traffic_flows.json
    merged_fast.log             (appended after every analysis)
"""
import os
import json
import shutil
import subprocess
import logging
from collections import defaultdict
from datetime import datetime

import config
import db
import geoip_service

log = logging.getLogger("analyzer")


# -- Suricata runner -----------------------------------------------------------

def analyze_pcap(pcap_path: str, project_id: int = None) -> bool:
    pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]

    # Determine output dirs
    if project_id:
        proj_dir  = db.get_project_dir(project_id)
        log_dir   = os.path.join(proj_dir, "logs", pcap_name)
    else:
        log_dir   = os.path.join(config.BASE_DIR, "logs", pcap_name)
    os.makedirs(log_dir, exist_ok=True)

    cmd = [config.SURICATA_BIN, "-r", pcap_path, "-l", log_dir, "-k", "none"]
    rules_file = os.path.join(config.RULES_DIR, "emerging-all.rules")
    if os.path.exists(rules_file):
        cmd += ["-S", rules_file]
    local_rules = os.path.join(config.RULES_DIR, "local.rules")
    if os.path.exists(local_rules):
        cmd += ["-S", local_rules]

    log.info("Running: %s", " ".join(cmd))

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
            log.warning("Suricata exited %d. stderr: %s",
                        result.returncode, result.stderr[:500])
    except subprocess.TimeoutExpired:
        log.error("Suricata timed out on %s", pcap_path)
        return False
    except FileNotFoundError:
        log.error("Suricata binary not found: %s", config.SURICATA_BIN)
        return False

    fast_log = os.path.join(log_dir, "fast.log")
    eve_log  = os.path.join(log_dir, "eve.json")

    # Append fast.log lines to project-level merged_fast.log
    if project_id:
        _append_fast_log(fast_log, project_id)

    has_high = _check_high_priority(fast_log)
    _extract_traffic_stats(pcap_path, os.path.basename(pcap_path),
                           project_id=project_id)

    if not has_high:
        auto_delete = db.get_setting("auto_delete_clean_pcap", "0") == "1"
        if auto_delete:
            log.info("No P1/P2 in %s - auto-delete enabled.", pcap_name)
            _safe_remove(pcap_path)
        else:
            _save_source_pcap(pcap_path, alert_count=0, project_id=project_id)
        return False

    alerts = _parse_eve_json(eve_log)
    log.info("%d alerts in %s", len(alerts), pcap_name)
    for alert in alerts:
        _process_alert(alert, pcap_path, project_id=project_id)

    _save_source_pcap(pcap_path, alert_count=len(alerts), project_id=project_id)
    return True


# -- merged_fast.log -----------------------------------------------------------

def _append_fast_log(fast_log_path: str, project_id: int):
    if not os.path.exists(fast_log_path):
        return
    proj_dir = db.get_project_dir(project_id)
    if not proj_dir:
        return
    merged = os.path.join(proj_dir, "merged_fast.log")
    try:
        with open(fast_log_path, "r", encoding="utf-8", errors="ignore") as src, \
             open(merged, "a", encoding="utf-8") as dst:
            dst.writelines(src)
    except OSError as e:
        log.warning("Could not append to merged_fast.log: %s", e)


# -- priority check ------------------------------------------------------------

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


# -- eve.json parser -----------------------------------------------------------

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


# -- per-alert processing ------------------------------------------------------

def _process_alert(event: dict, source_pcap: str, project_id: int = None):
    alert_obj = event.get("alert", {})
    priority  = alert_obj.get("severity", 3)
    if priority not in (1, 2):
        _store_alert(event, source_pcap, forensic_pcap=None,
                     project_id=project_id)
        return

    forensic_path = _extract_forensic(event, source_pcap,
                                       project_id=project_id)
    forensic_name = os.path.basename(forensic_path) if forensic_path else None
    _store_alert(event, source_pcap, forensic_pcap=forensic_name,
                 project_id=project_id)

    if forensic_path and os.path.exists(forensic_path):
        db.upsert_pcap(forensic_name, forensic_path,
                       os.path.getsize(forensic_path), 1,
                       pcap_type="forensic", project_id=project_id)


def _store_alert(event: dict, source_pcap: str, forensic_pcap,
                 project_id: int = None) -> int:
    alert_obj = event.get("alert", {})
    src_ip    = event.get("src_ip", "")
    return db.upsert_alert({
        "project_id":    project_id,
        "timestamp":     event.get("timestamp", datetime.now().isoformat()),
        "src_ip":        src_ip,
        "dst_ip":        event.get("dest_ip"),
        "src_port":      event.get("src_port"),
        "dst_port":      event.get("dest_port"),
        "proto":         event.get("proto"),
        "signature_id":  alert_obj.get("signature_id"),
        "signature":     alert_obj.get("signature"),
        "category":      alert_obj.get("category"),
        "severity":      alert_obj.get("severity", 3),
        "priority":      alert_obj.get("severity", 3),
        "source_pcap":   os.path.basename(source_pcap),
        "forensic_pcap": forensic_pcap,
        "country":       geoip_service.lookup(src_ip),
    })


# -- tshark forensic extraction ------------------------------------------------

def _extract_forensic(event: dict, source_pcap: str,
                       project_id: int = None):
    src_ip   = event.get("src_ip", "")
    dst_ip   = event.get("dest_ip", "")
    src_port = event.get("src_port")
    dst_port = event.get("dest_port")
    proto    = (event.get("proto") or "").lower()
    sig_id   = event.get("alert", {}).get("signature_id", 0)
    ts       = event.get("timestamp", datetime.now().isoformat())

    if proto in ("tcp", "udp") and src_port and dst_port:
        fwd = (f"(ip.src=={src_ip} && ip.dst=={dst_ip}"
               f" && {proto}.srcport=={src_port} && {proto}.dstport=={dst_port})")
        rev = (f"(ip.src=={dst_ip} && ip.dst=={src_ip}"
               f" && {proto}.srcport=={dst_port} && {proto}.dstport=={src_port})")
        display_filter = f"{fwd} || {rev}"
    else:
        display_filter = f"ip.addr=={src_ip} && ip.addr=={dst_ip}"

    ts_clean  = ts[:19].replace(":", "").replace("T", "_").replace("-", "")
    src_clean = src_ip.replace(".", "_")
    out_name  = f"{ts_clean}_{src_clean}_{sig_id}.pcap"

    forensics_dir = db.get_forensics_dir(project_id)
    os.makedirs(forensics_dir, exist_ok=True)
    out_path = os.path.join(forensics_dir, out_name)

    cmd = [config.TSHARK_BIN, "-r", source_pcap,
           "-Y", display_filter, "-w", out_path]
    try:
        subprocess.run(cmd, capture_output=True, timeout=120, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error("tshark failed: %s", e)
        return None

    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        log.info("Forensic PCAP saved: %s", out_name)
        return out_path
    return None


# -- traffic stats extraction --------------------------------------------------

def _extract_traffic_stats(pcap_path: str, source_pcap_name: str,
                            project_id: int = None):
    cmd = [
        config.TSHARK_BIN, "-r", pcap_path, "-n",
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "_ws.col.Protocol", "-e", "frame.len",
        "-E", "separator=|", "-E", "header=n",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, check=False,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error("tshark traffic extraction failed: %s", e)
        return

    agg = defaultdict(lambda: {"bytes": 0, "pkts": 0})
    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 4:
            continue
        src_ip = parts[0].strip()
        dst_ip = parts[1].strip()
        proto  = parts[2].strip() or "UNKNOWN"
        try:
            length = int(parts[3].strip())
        except ValueError:
            length = 0
        if not src_ip or not dst_ip:
            continue
        agg[(src_ip, dst_ip, proto)]["bytes"] += length
        agg[(src_ip, dst_ip, proto)]["pkts"]  += 1

    if not agg:
        return

    flows = [
        {
            "source_pcap": source_pcap_name,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "proto":       proto,
            "bytes":       stats["bytes"],
            "pkts":        stats["pkts"],
            "country_src": geoip_service.lookup(src_ip),
            "country_dst": geoip_service.lookup(dst_ip),
        }
        for (src_ip, dst_ip, proto), stats in agg.items()
    ]
    db.insert_flows_bulk(flows, project_id=project_id)
    log.info("Stored %d flows for %s", len(flows), source_pcap_name)


# -- move source PCAP into project sources/ ------------------------------------

def _save_source_pcap(pcap_path: str, alert_count: int,
                       project_id: int = None):
    basename = os.path.basename(pcap_path)
    if project_id:
        dest_dir = os.path.join(db.get_project_dir(project_id), "sources")
        os.makedirs(dest_dir, exist_ok=True)
    else:
        dest_dir = os.path.dirname(pcap_path)
    dest_path = os.path.join(dest_dir, basename)
    try:
        if os.path.abspath(pcap_path) != os.path.abspath(dest_path):
            shutil.move(pcap_path, dest_path)
        size = os.path.getsize(dest_path)
        db.upsert_pcap(basename, dest_path, size, alert_count,
                       pcap_type="source", project_id=project_id)
        log.info("Source PCAP -> sources/: %s (%d B, %d alerts)",
                 basename, size, alert_count)
    except OSError as e:
        log.error("Failed to save source PCAP (%s): %s", basename, e)


def _safe_remove(path: str):
    try:
        os.remove(path)
    except OSError as e:
        log.warning("Could not delete %s: %s", path, e)


# -- re-analysis ---------------------------------------------------------------

def reanalyze_pcap(pcap_path: str, project_id: int = None) -> bool:
    basename  = os.path.basename(pcap_path)
    pcap_name = os.path.splitext(basename)[0]

    if project_id:
        proj_dir = db.get_project_dir(project_id)
        log_dir  = os.path.join(proj_dir, "logs", pcap_name)
    else:
        log_dir = os.path.join(config.BASE_DIR, "logs", pcap_name)

    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)
    os.makedirs(log_dir, exist_ok=True)

    old_forensics = db.get_forensic_pcaps_by_source(basename,
                                                     project_id=project_id)
    forensics_dir = db.get_forensics_dir(project_id)
    for fname in old_forensics:
        fpath = os.path.join(forensics_dir, fname)
        if os.path.exists(fpath):
            _safe_remove(fpath)
        db.delete_pcap(fname, project_id=project_id)

    db.delete_alerts_by_source(basename, project_id=project_id)
    db.delete_flows_by_source(basename, project_id=project_id)

    cmd = [config.SURICATA_BIN, "-r", pcap_path, "-l", log_dir, "-k", "none"]
    rules_file = os.path.join(config.RULES_DIR, "emerging-all.rules")
    if os.path.exists(rules_file):
        cmd += ["-S", rules_file]
    local_rules = os.path.join(config.RULES_DIR, "local.rules")
    if os.path.exists(local_rules):
        cmd += ["-S", local_rules]

    env = os.environ.copy()
    extra = os.pathsep.join(filter(None, [
        config.SURICATA_DIR,
        config.NPCAP_DIR if os.path.isdir(config.NPCAP_DIR) else "",
    ]))
    env["PATH"] = extra + os.pathsep + env.get("PATH", "")

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       check=False, cwd=config.SURICATA_DIR, env=env)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error("Suricata error during re-analyze: %s", e)
        return False

    fast_log = os.path.join(log_dir, "fast.log")
    eve_log  = os.path.join(log_dir, "eve.json")

    if project_id:
        _append_fast_log(fast_log, project_id)

    has_high = _check_high_priority(fast_log)
    _extract_traffic_stats(pcap_path, basename, project_id=project_id)

    if not has_high:
        db.upsert_pcap(basename, pcap_path, os.path.getsize(pcap_path), 0,
                       pcap_type="source", project_id=project_id)
        return False

    alerts = _parse_eve_json(eve_log)
    for alert in alerts:
        _process_alert(alert, pcap_path, project_id=project_id)
    db.upsert_pcap(basename, pcap_path, os.path.getsize(pcap_path),
                   len(alerts), pcap_type="source", project_id=project_id)
    return True
