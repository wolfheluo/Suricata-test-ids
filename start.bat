@echo off
title Suricata IDS
chcp 65001 >nul
setlocal EnableDelayedExpansion

cd /d "%~dp0"

echo ============================================
echo  Suricata IDS - 環境自檢
echo ============================================
echo.

REM ── 讀取 config.py 中的路徑 ─────────────────────────────────────────────
REM 預設路徑（與 config.py 保持一致，若有修改請同步更新此處）
set "SURICATA_BIN=C:\Program Files\Suricata\suricata.exe"
set "DUMPCAP_BIN=C:\Program Files\Wireshark\dumpcap.exe"
set "TSHARK_BIN=C:\Program Files\Wireshark\tshark.exe"
set "GEOIP_DB=%~dp0GeoLite2-City.mmdb"

set CHECK_PASS=1

REM ── [CHECK 1] Suricata ───────────────────────────────────────────────────
if exist "%SURICATA_BIN%" (
    echo   [OK]  suricata.exe   : %SURICATA_BIN%
) else (
    echo   [!!]  suricata.exe   : 找不到  ^(%SURICATA_BIN%^)
    echo         請至 https://suricata.io/download/ 安裝 Suricata for Windows
    set CHECK_PASS=0
)

REM ── [CHECK 2] dumpcap ────────────────────────────────────────────────────
if exist "%DUMPCAP_BIN%" (
    echo   [OK]  dumpcap.exe    : %DUMPCAP_BIN%
) else (
    echo   [!!]  dumpcap.exe    : 找不到  ^(%DUMPCAP_BIN%^)
    echo         請至 https://www.wireshark.org/ 安裝 Wireshark（含 dumpcap）
    set CHECK_PASS=0
)

REM ── [CHECK 3] tshark ─────────────────────────────────────────────────────
if exist "%TSHARK_BIN%" (
    echo   [OK]  tshark.exe     : %TSHARK_BIN%
) else (
    echo   [!!]  tshark.exe     : 找不到  ^(%TSHARK_BIN%^)
    echo         請至 https://www.wireshark.org/ 安裝 Wireshark（含 tshark）
    set CHECK_PASS=0
)

REM ── [CHECK 4] GeoLite2-City.mmdb ────────────────────────────────────────
if exist "%GEOIP_DB%" (
    echo   [OK]  GeoLite2-City.mmdb : %GEOIP_DB%
) else (
    echo   [--]  GeoLite2-City.mmdb : 未找到（國別查詢將顯示 N/A）
    echo         可至 https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb 下載
    echo         並將 GeoLite2-City.mmdb 放置於專案根目錄（非必要，可繼續啟動）
)

REM ── [CHECK 5] Python ─────────────────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% == 0 (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo   [OK]  Python         : %%v
) else (
    echo   [!!]  Python         : 找不到，請安裝 Python 3.10+
    set CHECK_PASS=0
)

echo.

REM ── 若有關鍵元件缺失則中止 ───────────────────────────────────────────────
if "!CHECK_PASS!"=="0" (
    echo ============================================
    echo  [錯誤] 關鍵元件缺失，無法啟動。
    echo  請依上述提示安裝缺少的元件後重試。
    echo ============================================
    pause
    exit /b 1
)

echo ============================================
echo  自檢通過，開始啟動服務...
echo ============================================
echo.

REM ── 建立虛擬環境（首次執行）────────────────────────────────────────────
if not exist "venv\Scripts\python.exe" (
    echo [1/3] 建立 Python 虛擬環境...
    python -m venv venv
)

REM ── 安裝依賴 ─────────────────────────────────────────────────────────────
echo [2/3] 安裝 / 更新 Python 套件...
call venv\Scripts\pip install -q -r requirements.txt

REM ── 啟動 Flask ───────────────────────────────────────────────────────────
echo [3/3] 啟動 Flask (http://127.0.0.1:5000)
echo.
echo 按 Ctrl+C 停止服務
echo ============================================
call venv\Scripts\python app.py

pause
