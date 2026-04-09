"""
watcher.py – Background threads:
  • Capture poller  : polls captures/ every 2 s, queues completed PCAPs.
  • Analysis worker : dequeues PCAPs, runs analyzer.analyze_pcap().
  • dumpcap manager : starts / stops the dumpcap subprocess.
  • Traffic monitor : samples current PCAP file size every second → bytes/s.
"""
import os
import glob
import queue
import collections
import ipaddress
import subprocess
import threading
import logging
import time
from datetime import datetime

import config
import analyzer
import db

log = logging.getLogger("watcher")

# Rolling window length for live traffic history (seconds)
_TRAFFIC_WINDOW = 60


class CaptureWatcher:

    def __init__(self):
        self._analysis_queue: queue.Queue = queue.Queue()
        self._poll_thread:     threading.Thread | None = None
        self._worker_thread:   threading.Thread | None = None
        self._traffic_thread:  threading.Thread | None = None
        self._dumpcap_proc:    subprocess.Popen | None = None
        self._running          = False
        self._analyzing        = False
        self._lock             = threading.Lock()
        self.current_interface: str = ""

        # Shared set: every PCAP path that has ever been queued for analysis
        self._queued: set = set()

        # Live traffic ring-buffer: deque of (timestamp_str, bytes_per_sec)
        self._traffic_lock    = threading.Lock()
        self._traffic_history: collections.deque = collections.deque(
            maxlen=_TRAFFIC_WINDOW
        )
        self._total_captured_bytes: int = 0

    # ── public API ──────────────────────────────────────────────────────────

    def start(self):
        """Start background polling + analysis + traffic threads."""
        self._running = True
        self._poll_thread    = threading.Thread(target=self._poll_loop,    daemon=True, name="capture-poller")
        self._worker_thread  = threading.Thread(target=self._worker_loop,  daemon=True, name="analysis-worker")
        self._traffic_thread = threading.Thread(target=self._traffic_loop, daemon=True, name="traffic-monitor")
        self._poll_thread.start()
        self._worker_thread.start()
        self._traffic_thread.start()
        log.info("Watcher started.")

    def stop(self):
        """Signal threads to stop (they are daemons so they die with the process)."""
        self._running = False

    def start_capture(self, interface: str, filesize_kb: int = None, duration_secs: int = 0, exclude_ips=None):
        """Launch dumpcap on *interface*, optionally excluding a list of IPs via BPF filter."""
        self.stop_capture()
        if filesize_kb is None:
            filesize_kb = int(db.get_setting("capture_filesize_kb",
                                              str(config.DEFAULT_CAPTURE_FILESIZE_KB)))
        os.makedirs(config.CAPTURES_DIR, exist_ok=True)
        out_template = os.path.join(config.CAPTURES_DIR, "cap.pcap")

        cmd = [
            config.DUMPCAP_BIN,
            "-i", str(interface),
            "-b", f"filesize:{filesize_kb}",
            "-w", out_template,
        ]
        if duration_secs and duration_secs > 0:
            cmd += ["-b", f"duration:{duration_secs}"]

        # Build BPF capture filter to exclude specified IPs (validated)
        if exclude_ips:
            valid_ips = []
            for raw in exclude_ips:
                ip = str(raw).strip()
                try:
                    ipaddress.ip_address(ip)
                    valid_ips.append(ip)
                except ValueError:
                    log.warning("Skipping invalid exclude IP: %r", ip)
            if valid_ips:
                bpf = " and ".join(f"not host {ip}" for ip in valid_ips)
                cmd += ["-f", bpf]
                log.info("Capture filter: %s", bpf)

        log.info("Starting dumpcap: %s", " ".join(cmd))
        with self._lock:
            try:
                self._dumpcap_proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self.current_interface = str(interface)
                log.info("dumpcap PID=%d", self._dumpcap_proc.pid)
            except FileNotFoundError:
                log.error("dumpcap not found: %s", config.DUMPCAP_BIN)

    def stop_capture(self):
        """Terminate dumpcap and queue the last (partially written) PCAP for analysis."""
        with self._lock:
            if self._dumpcap_proc and self._dumpcap_proc.poll() is None:
                self._dumpcap_proc.terminate()
                try:
                    self._dumpcap_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._dumpcap_proc.kill()
                log.info("dumpcap stopped.")
            self._dumpcap_proc     = None
            self.current_interface = ""

        # After dumpcap exits, ALL files in captures/ are complete (no writer holds any).
        # Queue any that haven't been picked up yet by _poll_loop.
        files = sorted(
            f for f in glob.glob(os.path.join(config.CAPTURES_DIR, "*.pcap"))
            if os.path.isfile(f) and os.path.getsize(f) > 0
        )
        for f in files:
            if f not in self._queued:
                log.info("stop_capture: queuing final PCAP: %s", os.path.basename(f))
                self._queued.add(f)
                self._analysis_queue.put(f)


    def is_capturing(self) -> bool:
        with self._lock:
            return (self._dumpcap_proc is not None
                    and self._dumpcap_proc.poll() is None)

    def is_analyzing(self) -> bool:
        return self._analyzing

    def queue_size(self) -> int:
        return self._analysis_queue.qsize()

    def get_traffic_history(self) -> list:
        """Return list of {ts, bps, kbps} dicts for the last N seconds."""
        with self._traffic_lock:
            return list(self._traffic_history)

    def get_total_captured_bytes(self) -> int:
        with self._traffic_lock:
            return self._total_captured_bytes

    # ── capture poller ───────────────────────────────────────────────────────

    def _poll_loop(self):
        """
        Every 2 s scan captures/.  dumpcap always writes to the NEWEST file;
        all OLDER completed files are safe to analyze.
        """
        while self._running:
            try:
                files = sorted(
                    f for f in glob.glob(os.path.join(config.CAPTURES_DIR, "*.pcap"))
                    if os.path.isfile(f)
                )
                # All but the newest are complete (newest is still being written)
                completed = files[:-1] if self.is_capturing() else files
                for f in completed:
                    if f not in self._queued:
                        log.info("Queuing for analysis: %s", os.path.basename(f))
                        self._queued.add(f)
                        self._analysis_queue.put(f)
                # Prune shared set to avoid unbounded growth
                if len(self._queued) > 500:
                    self._queued = set(list(self._queued)[-200:])
            except Exception as e:
                log.error("Poll error: %s", e)
            time.sleep(2)

    # ── analysis worker ──────────────────────────────────────────────────────

    def _worker_loop(self):
        """Pick PCAPs from queue and analyze them one by one."""
        while self._running:
            try:
                pcap_path = self._analysis_queue.get(timeout=1)
            except queue.Empty:
                continue
            if not os.path.exists(pcap_path):
                continue
            self._analyzing = True
            try:
                analyzer.analyze_pcap(pcap_path)
                self._enforce_capture_retention()
            except Exception as e:
                log.error("Analysis error for %s: %s", pcap_path, e)
            finally:
                self._analyzing = False
                self._analysis_queue.task_done()

    # ── traffic monitor ──────────────────────────────────────────────────────

    def _traffic_loop(self):
        """Sample the active capture file size every second; compute bytes/s."""
        prev_size   = 0
        prev_cumul  = 0
        while self._running:
            time.sleep(1)
            if not self.is_capturing():
                # Push a zero-rate tick so the chart doesn't stall
                ts = datetime.now().strftime("%H:%M:%S")
                with self._traffic_lock:
                    self._traffic_history.append({"ts": ts, "bps": 0, "kbps": 0.0})
                prev_size = 0
                continue
            try:
                # Active file is the newest one in captures/
                files = sorted(
                    f for f in glob.glob(os.path.join(config.CAPTURES_DIR, "*.pcap"))
                    if os.path.isfile(f)
                )
                if not files:
                    continue
                active = files[-1]
                cur_size = os.path.getsize(active)
                delta    = max(0, cur_size - prev_size)

                # Accumulate across rotations: if file shrank (new rotation), add old size
                if cur_size < prev_size:
                    delta = cur_size
                    prev_cumul += prev_size

                bps  = delta          # bytes in the last second
                kbps = round(delta / 1024, 1)
                ts   = datetime.now().strftime("%H:%M:%S")
                with self._traffic_lock:
                    self._traffic_history.append({"ts": ts, "bps": bps, "kbps": kbps})
                    self._total_captured_bytes = prev_cumul + cur_size
                prev_size = cur_size
            except Exception as e:
                log.debug("Traffic monitor error: %s", e)

    # ── retention cleanup ────────────────────────────────────────────────────

    def _enforce_capture_retention(self):
        """Delete oldest capture files if count exceeds max_capture_files."""
        max_files = int(db.get_setting("max_capture_files",
                                        str(config.DEFAULT_MAX_CAPTURE_FILES)))
        files = sorted(
            f for f in glob.glob(os.path.join(config.CAPTURES_DIR, "*.pcap"))
            if os.path.isfile(f)
        )
        # Completed files: exclude the file dumpcap is actively writing
        completed = files if not self.is_capturing() else files[:-1]
        excess    = len(completed) - max_files
        # Delete only the oldest `excess` files (files are sorted oldest-first)
        for f in completed[:excess]:
            log.info("Retention: removing old capture %s", os.path.basename(f))
            try:
                os.remove(f)
            except OSError:
                pass
