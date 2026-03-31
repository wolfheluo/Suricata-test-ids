"""
geoip_service.py – Offline GeoIP country lookup via MaxMind GeoLite2-City.mmdb
Place GeoLite2-City.mmdb in the project root before running.
Download (free account required): https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""
import os
import socket
import config

_reader = None


def _check_internet(host="8.8.8.8", port=53, timeout=3) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except OSError:
        return False


def init_geoip():
    global _reader
    if not os.path.exists(config.GEOIP_DB):
        print("[GeoIP] GeoLite2-City.mmdb not found – country lookup disabled.")
        print("        Download it from https://dev.maxmind.com and place it in the project root.")
        return
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(config.GEOIP_DB)
        print(f"[GeoIP] Loaded {config.GEOIP_DB}")
    except Exception as e:
        print(f"[GeoIP] Failed to load mmdb: {e}")
        _reader = None


def lookup(ip: str) -> str:
    if _reader is None:
        return "N/A"
    try:
        response = _reader.city(ip)
        return response.country.iso_code or "N/A"
    except Exception:
        return "N/A"
