<p align="center">
  <img src="frontend/public/favicon.svg" alt="CF Tunnel Logo" width="80">
</p>

<h1 align="center">Cloudflare Tunnel WebGUI — PaaS 版</h1>

<p align="center">
  <strong>在瀏覽器裡，把 WOOW PaaS 工作區裡的服務透過 Cloudflare tunnel 開到外網。</strong>
</p>

<p align="center">
  <a href="README.md">English</a> &bull;
  <a href="docs/paas-api.md">API 契約</a>
</p>

---

這是 WOOW Cloudflare Tunnel 網頁管理介面的第三個版本，另外兩個是
[Podman 版](https://github.com/WOOWTECH/Woow_podman_cf_tunnel_webgui)和
[Home Assistant 外掛版](https://github.com/WOOWTECH/Woow_ha_cf_tunnel_webgui)。
三版的頁面一樣是五頁，三種連結方式也相同：

| 頁面 | 功能 |
|---|---|
| Dashboard | tunnel 狀態（與 Cloudflare 的連線數）、啟動／停止／重啟 |
| PaaS 連結 | 用裝置碼連結 WOOW PaaS 的 **Security Access**、檢查路由、連線、釋放、測試外部網址 |
| Setup | **客製連結**：登入你自己的 Cloudflare 帳號、建立 tunnel、建 DNS 路由 |
| Config | **Token 連結**：貼 tunnel token，設定路由、預設轉送、post-quantum、log 等級、執行參數 |
| Logs | 即時 cloudflared 紀錄，密鑰自動遮蔽 |

PaaS 版多出來的是「**工作區服務**」：WebGUI 以一個服務的身分跑在 PaaS 工作區裡，
會列出同一個工作區的其他服務。勾選五套 pi agent、取好名稱，一次就能開通：

- **PaaS 連結**：WebGUI 透過平台把網址加進連結的 Security Access（`<名稱>.woowtech.io`），平台再推到 tunnel。
- **Setup（客製連結）**：網址寫進本機的 ingress 設定，並用你的 Cloudflare 登入建立 DNS 記錄。
- **Config（Token 連結）**：token 模式的規則只能在 Cloudflare 儀表板設定，清單會列出要填的內容。

## 運作方式

- 程式只聽 127.0.0.1；pod 唯一的入口是 nginx 登入代理，帳號 `admin`，密碼就是平台上這個服務的管理員密碼（在平台重設後 pod 會重啟套用）。
- cloudflared 是程式的子行程，意外結束會自動重啟（間隔 2、5、10、30、60 秒）；存活檢查只看程式本身，tunnel 斷線不會讓 pod 重啟。
- `/data`（1Gi 磁碟）存設定、tunnel token、`cert.pem`、`tunnel.json` 與 PaaS 連結狀態，檔案一律 0600。
- 路由的服務位址是工作區內的位址，例如 `http://svc-11111111-pi-agent:8080`；工作區的網路規則讓這個 pod 連得到同工作區的每個服務，其他工作區連不到。
- 列出服務用的權限只限本工作區、只能讀 Service 與 EndpointSlice。

chart 的設定值、開發與測試指令見 [README.md](README.md)。
