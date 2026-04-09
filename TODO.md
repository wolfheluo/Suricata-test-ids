# Suricata IDS 優化 TODO LIST
> 最後更新：2026-04-09

---

## 🐛 已知 Bug（高優先，建議優先修復）

### B-1 `reanalyzePcap` 輪詢邏輯立即停止
**位置：** `templates/pcap_library.html` → `reanalyzePcap()`
**問題：** `const f = files.find(x=>x.filename===filename)` 只要檔案存在就是 truthy，導致第一輪查詢（2 秒後）就清除計時器，根本沒有等待分析完成。
**建議修復：** 改為追蹤 `alert_count` 是否發生變化，或後端改用 WebSocket / SSE 推送分析狀態。

```javascript
// 修復前（立即停止）
if (tries >= 30 || f) { clearInterval(timer); ... }

// 修復後（需要 is_analyzing 旗標變回 false）
if (tries >= 30 || (f && !isAnalyzing)) { clearInterval(timer); ... }
```

---

### B-2 `_queued` set 清理順序無法保證
**位置：** `watcher.py` → `_poll_loop()`
**問題：** `set(list(self._queued)[-200:])` — Python `set` 無序，`list(set)` 不保證是「最新的 200 個」。長時間運行後可能重複分析舊 PCAP。
**建議修復：** 改用 `collections.OrderedDict` 取代 `set`，保留插入順序。

---

### B-3 `SECRET_KEY` 每次啟動都重新產生
**位置：** `config.py` → `SECRET_KEY = secrets.token_hex(32)`
**問題：** Flask Session 在服務重啟後全部失效。若未來加入登入功能會造成問題。目前雖無登入，但這是潛在 bug。
**建議修復：** 改為從環境變數或 `.env` 檔案讀取，若不存在則產生後寫入。

---

### B-4 GeoIP `_check_internet()` 為 Dead Code
**位置：** `geoip_service.py`
**問題：** `_check_internet()` 函數定義了但從未被呼叫，佔用程式碼空間並造成困惑。
**建議修復：** 直接刪除此函數。

---

### B-5 `api_alert_preview` / `api_alert_hexdump` 同步阻塞主執行緒
**位置：** `app.py` → `api_alert_preview()`, `api_alert_hexdump()`
**問題：** 大型 PCAP 的 tshark 呼叫最長 30 秒，會阻塞整個 Flask Worker。
**建議修復：** 加入 `timeout` 回傳提示，或改用非同步處理（`concurrent.futures.ThreadPoolExecutor`）。

---

### B-6 `requirements.txt` 無版本鎖定
**位置：** `requirements.txt`
**問題：** 四個套件均無版本號，任何一個套件有 Breaking Change 都可能導致系統無法啟動。
**建議修復：** 以 `pip freeze > requirements.txt` 鎖定版本。

```
Flask==3.1.0
watchdog==6.0.0
geoip2==4.8.1
ijson==3.3.0
```

---

## ⚡ 效能優化

### P-1 SQLite 缺少關鍵索引（查詢越來越慢）
**位置：** `db.py` → `SCHEMA`
**問題：** `alerts`、`traffic_flows` 表在資料量增大後，`WHERE` 查詢無索引會全表掃描。`upsert_alert` 的 dedup 查詢每次都掃描整表。
**建議修復：** 在 `SCHEMA` 內補充索引：

```sql
CREATE INDEX IF NOT EXISTS idx_alerts_sig_ip     ON alerts(signature_id, src_ip, last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_created    ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_source      ON traffic_flows(source_pcap);
CREATE INDEX IF NOT EXISTS idx_flows_created     ON traffic_flows(created_at);
CREATE INDEX IF NOT EXISTS idx_pcap_type         ON pcap_files(pcap_type);
```

---

### P-2 `_conn()` 每次查詢都建新連線
**位置：** `db.py` → `_conn()`
**問題：** SQLite 雖輕量，但每次呼叫都 open/close 連線有不必要的 overhead，尤其在高頻率 `/api/dashboard`（每 5 秒輪詢）時。
**建議修復：** 改用 thread-local 連線快取（`threading.local()`）。

---

### P-3 `_extract_traffic_stats` 無大檔案保護
**位置：** `analyzer.py` → `_extract_traffic_stats()`
**問題：** 對 200MB PCAP，tshark 可能輸出幾百萬行，全部讀入記憶體聚合。超過 1GB 的 PCAP 可能造成 OOM。
**建議修復：** 使用 `ijson`（已安裝！）或分批讀取 tshark 輸出，每批 10000 行 insert 一次，避免一次性堆積在記憶體。

---

### P-4 `insert_flows_bulk` 沒有批次大小限制
**位置：** `db.py` → `insert_flows_bulk()`
**問題：** 單次 `executemany` 插入數十萬筆，SQLite 的單次 transaction 會鎖住很長時間。
**建議修復：** 分批插入，每批 5000 筆。

---

### P-5 Suricata 啟動環境設定程式碼重複
**位置：** `analyzer.py` → `analyze_pcap()` 與 `reanalyze_pcap()`
**問題：** 相同的 `env["PATH"]` 組裝邏輯在兩個函數中各寫了一遍，違反 DRY 原則，未來修改容易漏改其中一處。
**建議修復：** 抽出 `_build_suricata_env()` helper 函數共用。

---

## 🔒 安全強化

### S-1 規則線上更新未驗證完整性
**位置：** `app.py` → `api_rules_update()`
**問題：** 直接從 Emerging Threats URL 下載規則覆蓋，沒有驗證 HTTPS 憑證、內容 Hash（官方提供 MD5/SHA256）或檔案格式，可能被中間人攻擊替換規則。
**建議修復：** 下載後比對官方提供的 SHA256，驗證後再覆蓋，或至少確認 HTTPS 連線。

---

### S-2 前端 `innerHTML` 批次拼接存在 XSS 潛力
**位置：** `templates/pcap_library.html`、`templates/events.html`、`templates/dashboard.html`
**問題：** `tbody.innerHTML += \`<tr>...\${f.filename}...\`` 直接插入資料，若資料庫中的 filename 或 signature 包含 `<script>` 標籤會觸發 XSS。雖然資料是系統產生的，但仍屬不良實踐。
**建議修復：** 使用 DOM API（`createElement`、`textContent`）替代 innerHTML 拼接，或統一使用 `escapeHtml()` 工具函數。

---

### S-3 缺少 API 請求速率限制
**位置：** `app.py` 全部 API 路由
**問題：** `/api/capture/start`、`/api/pcap/<filename>/reanalyze` 等操作型 API 沒有速率限制，可被本機或內網惡意程序濫用（短時間內啟動大量分析任務堆積 Queue）。
**建議修復：** 使用 `flask-limiter` 對操作型 API 設定速率限制（如每分鐘最多 60 次）。

---

## ✨ 功能增強

### F-1 缺少告警導出功能（CSV / JSON）
**位置：** `app.py` / `templates/events.html`
**建議：** 在告警頁面新增「匯出 CSV」按鈕，呼叫 `/api/alerts/export?format=csv`。後端用 Python `csv` 模組串流輸出，避免一次性載入全部資料。

---

### F-2 缺少 Suricata / Wireshark 健康檢查
**位置：** `app.py`
**問題：** 系統啟動後無法快速判斷外部工具是否可用，只有在實際分析時才會報錯。
**建議：** 新增 `/api/healthcheck` API，回傳各元件狀態：

```json
{
  "suricata": { "ok": true, "version": "7.0.3" },
  "tshark":   { "ok": true, "version": "4.4.0" },
  "geoip":    { "ok": true },
  "disk":     { "free_gb": 45.2, "warning": false }
}
```

並在儀表板側錄控制列旁顯示元件狀態圖示。

---

### F-3 缺少磁碟空間告警
**位置：** `watcher.py`、`templates/dashboard.html`
**問題：** Forensics 目錄可能在無感知的情況下撐爆磁碟，尤其高流量時。
**建議：** 在 `_enforce_capture_retention()` 後加入磁碟空間檢查，若剩餘 < 2GB 則：
  1. 記錄 WARNING log
  2. API `/api/dashboard` 回傳 `disk_warning: true`
  3. 儀表板顯示警示橫幅

---

### F-4 `reanalyze` 無進度回報
**位置：** `app.py` → `/api/pcap/<filename>/reanalyze`、前端輪詢邏輯
**問題：** 目前只回傳 `{"queued": true}`，前端無從得知目前分析狀態（排隊中/分析中/完成）。
**建議：** 後端新增 `/api/status` 端點，回傳分析 Queue 大小與當前正在處理的 PCAP 名稱；或改以 Server-Sent Events（SSE）主動推送。

---

### F-5 `forensics_dir` 變更後舊有記錄路徑失效
**位置：** `app.py` → `api_settings_post()`，`db.py` → `pcap_files.filepath`
**問題：** 在設定頁更改 Forensics 儲存路徑時，資料庫中所有 `pcap_files.filepath` 仍指向舊路徑，造成下載/預覽全部失敗。
**建議修復：** 變更路徑後，呼叫 `UPDATE pcap_files SET filepath = REPLACE(filepath, old_path, new_path)`，並提示用戶手動搬移舊檔案。

---

### F-6 缺少批次重新分析功能
**位置：** `templates/pcap_library.html`
**建議：** 在批次刪除旁新增「批次重新分析」按鈕，對已勾選的 PCAP 依序呼叫 `/api/pcap/<filename>/reanalyze`，並顯示整體進度。

---

### F-7 告警頁面缺少「按 Signature 分組」視圖
**位置：** `templates/events.html`
**建議：** 新增分頁/切換按鈕，除「flat 列表」外提供「按規則分組」視圖，每行顯示：規則名稱、觸發次數、最後一次觸發時間、涉及 IP 數量。

---

## 🧹 程式碼整理

### C-1 `start.bat` 與 `config.py` 路徑設定重複維護
**問題：** `SURICATA_BIN`、`TSHARK_BIN` 等路徑在 `config.py` 和 `start.bat` 各維護一份，容易不同步。
**建議：** `start.bat` 中直接 `python -c "import config; print(config.SURICATA_BIN)"` 讀取路徑，或改由 `config.py` 的值為唯一來源。

---

### C-2 `ijson` 套件已安裝但未使用
**位置：** `requirements.txt`
**問題：** `ijson` 安裝了但整個專案中沒有任何地方 `import ijson`，是廢棄依賴。
**建議：** 在 `_extract_traffic_stats` 改用 ijson 串流解析 PCAP（見 P-3），或若確認不需要則從 requirements.txt 移除。

---

### C-3 `_check_high_priority` 與 `_parse_eve_json` 邏輯不一致
**位置：** `analyzer.py`
**問題：** `_check_high_priority` 從 `fast.log` 判斷是否有高優先告警；實際儲存告警時從 `eve.json` 的 `severity` 欄位判斷。兩者來源不同，可能在邊緣情況下不一致（fast.log Priority 與 eve.json severity 對應關係取決於 Suricata 設定）。
**建議：** 統一改為直接解析 `eve.json`，放棄 fast.log 依賴：先 parse eve.json 後，判斷是否有 `severity in (1, 2)` 的告警，再決定後續流程。

---

## 優先級總覽

| 優先級 | 項目 | 類別 |
|--------|------|------|
| 🔴 立刻修 | B-1 reanalyzePcap 輪詢立即停止 | Bug |
| 🔴 立刻修 | B-6 requirements.txt 無版本 | Bug |
| 🔴 立刻修 | P-1 SQLite 缺少索引 | 效能 |
| 🟠 近期修 | B-2 _queued set 順序問題 | Bug |
| 🟠 近期修 | B-5 API 同步阻塞 | Bug |
| 🟠 近期修 | P-3 大 PCAP 流量解析 OOM | 效能 |
| 🟠 近期修 | S-2 innerHTML XSS | 安全 |
| 🟠 近期修 | F-5 forensics_dir 路徑失效 | 功能 |
| 🟡 計劃中 | F-2 健康檢查 API | 功能 |
| 🟡 計劃中 | F-3 磁碟空間告警 | 功能 |
| 🟡 計劃中 | F-4 分析進度回報 | 功能 |
| 🟡 計劃中 | C-3 fast.log vs eve.json 統一 | 維護 |
| 🟢 有空再做 | F-1 告警 CSV 導出 | 功能 |
| 🟢 有空再做 | F-6 批次重分析 | 功能 |
| 🟢 有空再做 | F-7 按 Signature 分組 | 功能 |
| 🟢 有空再做 | S-1 規則更新完整性驗證 | 安全 |
| 🟢 有空再做 | C-1 bat/config 路徑同步 | 維護 |
