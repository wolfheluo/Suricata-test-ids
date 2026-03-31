# 🛡️ Suricata 智慧型 IDS 工具開發計畫書

---

## 一、系統架構設計 (System Architecture)

系統採用四層式架構，確保高可用性與數據完整性：

```
┌─────────────────────────────────────────────┐
│           呈現層 (Frontend UI)               │
│           Flask + Jinja2 + Chart.js          │
├─────────────────────────────────────────────┤
│         數據處理層 (Backend Engine)           │
│          Python (Flask) + Scapy              │
├─────────────────────────────────────────────┤
│           持久化層 (Storage)                  │
│      SQLite / PostgreSQL + File System       │
├─────────────────────────────────────────────┤
│          數據採集層 (Data Source)             │
│    Suricata (eve-log + payload + pcap)       │
└─────────────────────────────────────────────┘
```

| 層級 | 元件 | 說明 |
|------|------|------|
| 數據採集層 | `dumpcap` (Npcap/WinPcap) | 在 Windows 上監聽網卡，每 200MB 自動輪替產生 PCAP 檔案 |
| 數據採集層 | Suricata (`-r` 離線模式) | 不監聽網卡，直接讀取已完成的 PCAP 檔案進行分析，輸出 `eve.json` |
| 數據處理層 | Python 腳本 (`watchdog`) | 監控 PCAP 目錄，偵測新完成檔案後觸發 Suricata 分析；同時監控 `eve.json` 處理告警 |
| 持久化層 | SQLite / PostgreSQL | 儲存警報事件與流量統計 |
| 持久化層 | File System | 儲存側錄 PCAP 與告警關聯的取證 PCAP 片段 |
| 呈現層 | Flask (Jinja2 Template) | 內建開發伺服器直接提供 HTML 頁面，無需 Apache / Nginx |

---

## 二、核心功能規格 (Core Functional Specs)

### 1. 流量統計模組 (Traffic Statistics)

- **即時吞吐量**：讀取 `stats.log` 或 `eve.json` 中的 `stats` 欄位

#### 監控指標

| 指標 | 說明 |
|------|------|
| $Packets_{total}$ | 總封包數 |
| $Bytes_{total}$ | 總流量大小 |
| PPS | 每秒封包數 (Packets Per Second) |
| BPS | 每秒位元數 (Bits Per Second) |

---

### 2. 惡意告警與精準取證 (Alert & Forensics)

#### 側錄 + 離線分析機制（Windows 無需 Docker）

> **設計原則**：由 `dumpcap` 負責在 Windows 上持續側錄網卡，每 200MB 自動輪替產生 PCAP 檔案；Suricata 不監聽任何網卡，改以 `-r` 離線模式逐一分析已完成的 PCAP 檔案，完全相容 Windows 原生環境。

**整體流程：**

```
網路流量
  │
  └─► dumpcap (Npcap)
        │  每 200MB 輪替一個新檔
        ▼
  PCAP 側錄目錄
  capture_0001.pcap  (寫入中，dumpcap 鎖定)
  capture_0002.pcap  ← 已完成
  capture_0003.pcap  ← 已完成
        │
        │  Python watchdog 偵測「舊檔完成」
        ▼
  Suricata -r capture_0002.pcap -l logs/
        │
        ├─► fast.log（每條告警含 Priority 欄位）
        │         │
        │   解析完成後檢查 fast.log
        │         │
        │    ┌────┴────┐
        │    │         │
        │  有 Priority=1   無 Priority=1
        │  或 Priority=2   且無 Priority=2
        │    │         │
        │    ↓         ↓
        │  保留側錄  立即刪除側錄
        │  PCAP      PCAP（釋放空間）
        │    │
        │  偵測到高優先告警
        │    ↓
        └─► tshark 從保留的 PCAP 擷取對應封包
                  ↓
            永久保存取證 PCAP
```

| 機制 | 說明 |
|------|------|
| **dumpcap 側錄** | `dumpcap -i <iface> -b filesize:204800 -w captures\cap.pcap` 每 200MB 自動輪替，持續產出帶序號的 PCAP 檔案 |
| **Python 檔案監控** | `watchdog` 監聽 `captures\` 目錄，當 dumpcap 開始寫入新檔（即上一個 200MB 檔案確定關閉）時，觸發 Suricata 分析前一個已完成檔案 |
| **Suricata 離線分析** | `suricata -r <pcap_file> -l <log_dir>` 逐檔分析，輸出格式與線上模式完全相同 |
| **Priority 判斷刪除** | Suricata 分析完成後，解析同一 log 目錄下的 `fast.log`：若**無任何** `Priority: 1` 或 `Priority: 2` 的告警，立即刪除對應側錄 PCAP，釋放磁碟空間；有高優先告警則保留 |
| **ALERT 取證截取** | 確認保留側錄 PCAP 後，以 `tshark -r <src_pcap> -Y "ip.addr==X and frame.time>=T"` 擷取 Priority 1/2 告警對應封包片段，永久保存至取證目錄 |
| **自動命名** | 格式：`{timestamp}_{src_ip}_{signature_id}.pcap`，與告警事件一對一綁定 |
| **輪替保留策略** | 保留最近 N 個**尚未判斷完成**的側錄 PCAP（預設 10 個，約 2GB）；判斷後無高優先告警者立即刪除，有告警者取證後亦可刪除原始側錄，僅保留取證 PCAP 片段 |

---

### 3. Top-N 流量分析 (Top-N Traffic Analysis)

| 分析維度 | 說明 |
|----------|------|
| Top 10 來源 IP | 依流量大小 / 警報觸發次數排序，附帶國別標示 |
| Top 10 來源國別 | 依告警觸發次數統計來源國家分布 |
| Top 10 目的 Port | 快速識別掃描或異常服務存取 |
| Top 10 觸發規則 | 依告警頻率排序，協助調整規則優先級 |

- 支援時間範圍篩選：最近 1h / 24h / 7d

#### 國別解析機制（GeoIP）

系統啟動時自動偵測網路狀態，決定 `.mmdb` 的取得方式：

```
系統啟動
  │
  ├─► 偵測是否可連外網
  │     │
  │     ├─ 可連線 ──► 自動下載 / 更新 GeoLite2-City.mmdb
  │     │
  │     └─ 無法連線 ──► 使用本地已存在的 .mmdb（純內網模式）
  │                        若本地也不存在 → 國別欄位顯示 "N/A"
  │
  └─► geoip2 讀取本地 .mmdb，所有查詢完全離線
```

> **內網部署備註**：離線環境請在初次部署時預先放置 `GeoLite2-City.mmdb` 於專案根目錄，後續運行無需任何外部連線。

---

### 4. 告警去重與抑制 (Alert Deduplication)

- 相同 `signature_id` + 相同來源 IP 在可配置時間窗口（預設 60 秒）內合併為一筆記錄
- 合併後顯示 **Hit Count**（觸發次數），而非重複列出
- 防止短時間暴力掃描或埠掃描淹沒儀表板

---

### 5. 規則管理 (Rule Management)

#### 規則自動偵測與更新機制

系統啟動時自動偵測網路狀態，決定規則取得方式：

```
系統啟動
  │
  ├─► 偵測是否可連外網
  │     │
  │     ├─ 可連線 ──► 自動下載 / 更新 emerging-all.rules（Emerging Threats）
  │     │                  ↓
  │     │             熱重載 Suricata（suricatasc reload-rules）
  │     │
  │     └─ 無法連線 ──► 使用本地現有 .rules 檔案（純內網模式）
  │                         若本地也不存在 → 警告提示，Suricata 無法啟動
  │
  └─► 規則載入完成，開始監聽
```

| 機制 | 說明 |
|------|------|
| **自動更新** | 有外網時從 `rules.emergingthreats.net` 下載 `emerging-all.rules` |
| **離線回退** | 無外網時沿用本地已存在的規則檔，系統正常運行 |
| **手動匯入** | 支援上傳自訂 `.rules` 檔案，系統自動熱重載引擎 |
| **個別啟用 / 停用** | 每條規則提供獨立開關，無需整包重傳重載 |
| **規則編輯器** | 支援語法高亮與基本語法驗證（格式錯誤即時提示） |
| **版本管理** | 保留歷史規則版本，支援一鍵回滾 |

> **內網部署備註**：離線環境請於初次部署時預先放置 `emerging-all.rules`，後續運行無需外部連線。

---

### 6. PCAP 管理 (PCAP Management)

- 列出所有留存的 PCAP（時間戳、檔案大小、對應告警事件連結）
- **線上預覽**：後端呼叫 `tshark -r` 解析後回傳封包摘要，無需下載即可快速檢視
- 支援單筆 / 批次刪除
- 容量超過設定閾值時，自動刪除最舊檔案

---

## 三、技術棧選型 (Technology Stack)

| 類別 | 技術 | 選型理由 |
|------|------|----------|
| 核心引擎 | Suricata 8.0+ (`-r` 離線模式) | 業界標準 IDS 引擎；Windows 上以 `-r <pcap>` 取代直接監聽網卡 |
| 封包側錄 | `dumpcap` (Wireshark / Npcap) | Windows 原生網卡監聽，每 200MB 自動輪替 PCAP 檔案 |
| 後端 / 前端 | Python (Flask) | 同時提供 API 端點與 HTML 頁面渲染，單一程序啟動即可，無需獨立前端建置流程 |
| 檔案監控 | `watchdog` (Python) | 監聽側錄目錄，新 PCAP 完成後自動觸發 Suricata 分析 |
| 日誌解析 | `ijson` | 支援大型 JSON 串流解析 `eve.json` |
| 取證擷取 | `tshark` (Wireshark CLI) | 從側錄 PCAP 擷取告警對應封包；PCAP 線上預覽 |
| 國別解析 | `geoip2` + `GeoLite2-City.mmdb` | 本地離線查詢，有網路時自動更新 `.mmdb` |
| 前端框架 | Jinja2 + Bootstrap 5 | Flask 內建模板引擎，搭配 Bootstrap 快速排版，無需 Node.js 建置環境 |
| 圖表庫 | Chart.js (CDN) | 純 JavaScript 圖表，透過 `<script>` 引入即可，無需打包工具 |

---

## 四、前端 UI 介面設計 (UI/UX Design)

> 所有頁面由 Flask 的 Jinja2 模板引擎渲染，Flask 內建開發伺服器（`flask run`）直接提供服務，**不需要 Apache、Nginx 或任何反向代理**。圖表使用 Chart.js 透過 CDN 引入，無需 Node.js 或任何前端建置工具。

### 介面 A：實時監控儀表板 (Dashboard)

| 區域 | 內容 |
|------|------|
| 頂部資訊列 | 系統狀態 (Running / Stopped)、當前側錄網卡 (dumpcap)、今日總警報數 |
| 中央圖表 — 折線圖 | 流量趨勢：PPS 與 Mbps 即時曲線 |
| 中央圖表 — 餅圖 | 威脅分類佔比：Severity 1 / 2 / 3 |
| 底部列表 | 最新 5 條警報簡要資訊 |

---

### 介面 B：警報事件詳情 (Event List & Detail)

**列表欄位**：時間、來源 IP、目的 IP、警報名稱、嚴重性、**Hit Count**

**交互功能**：
- 點擊任一警報可展開詳情面板
- **線上 PCAP 預覽**：在詳情頁直接顯示 `tshark` 解析的封包摘要，無需下載
- **取證按鈕**：醒目的「下載 PCAP」藍色按鈕
- **原始數據**：顯示該封包的十六進制 (Hex Dump) 預覽

---

### 介面 C：PCAP 管理 (PCAP Library)

- 列出所有留存 PCAP（時間戳、大小、對應告警事件連結）
- 線上預覽 / 下載 / 單筆刪除 / 批次刪除
- 儲存容量使用量顯示與自動清理閾值設定

### 介面 D：系統配置 (Settings)

- 側錄網卡選擇（由 `dumpcap -D` 列出所有可用網卡，使用者下拉選取）
- PCAP 輪替大小設定（預設 200MB，可調整）
- 側錄 PCAP 保留數量（預設保留最新 10 個，約 2GB；超量自動刪除最舊）
- 告警去重時間窗口設定（預設 60 秒）
- 規則管理：手動上傳 `.rules` 檔案、啟用 / 停用個別規則開關
- Suricata 規則編輯器（含語法高亮與格式驗證）
- 規則版本紀錄（支援回滾至前一版本）

---

## 五、開發里程碑 (Milestones)

| 階段 | 目標 | 預計產出 |
|------|------|----------|
| Phase 1 | 環境建置與數據採集 | `dumpcap` 正常側錄並輪替 PCAP；Suricata 以 `-r` 模式分析 PCAP 並輸出 `eve.json` |
| Phase 2 | 後端 / 前端開發 | Flask 同時提供 API 端點與 HTML 頁面；警報查詢、取證下載端點完成 |
| Phase 3 | 儀表板頁面開發 | Dashboard 與事件列表頁面完成（Jinja2 + Chart.js）|
| Phase 4 | 整合測試 | 端對端流程驗證（封包 → 警報 → PCAP 下載） |
| Phase 5 | 部署與文件 | Docker Compose 打包、使用手冊撰寫 |

---

## 六、風險評估 (Risk Assessment)

| 風險 | 說明 | 緩解方案 |
|------|------|----------|
| 取證遺漏 | ALERT 觸發時對應 PCAP 已被輪替刪除 | 調大保留數量（`-b`）確保側錄 PCAP 存活至 Suricata 分析完成後再進行輪替清理 |
| 儲存空間耗盡 | 大量 ALERT 觸發造成 PCAP 累積 | 僅留存 ALERT PCAP + 自動清理超量舊檔 |
| 儀表板被警報淹沒 | 暴力掃描產生大量重複告警 | 告警去重機制（60 秒窗口合併 + Hit Count 顯示） |
| 規則誤報 | 過多 False Positive | 個別規則停用開關 + 規則編輯器快速調整 |
| 規則更新中斷服務 | 重載規則時 Suricata 短暫停止分析 | 離線模式下每次分析均為獨立進程，規則更新在下一個 PCAP 啟動時自動生效，無需熱重載 |
| 分析延遲 | 200MB 側錄檔未填滿時分析不觸發 | （低流量環境）可增加 `-b duration:300`，每 5 分鐘強制輪替一次新檔，確保定期觸發分析 |
| 效能瓶頸 | 高流量環境下日誌解析延遲 | 採用 `ijson` 串流解析，避免一次性載入大檔 |
