# cardeck-bridge

CarDeck 远程调试桥——一套面向「远程排障 + AI agent」的调试服务：

```
车机 ←→ 手机(CarDeck remoteDebug 变体) ←WSS/WS─ 内网穿透 ─ 本服务(WS) ⇄ MCP(stdio) → AI agent
```

一台普通电脑跑本服务即可：

- **设备面**（WebSocket，默认 `:8787`）：手机上安装 CarDeck 的 **remoteDebug 变体**（`assembleRemoteDebug` 产物，包名带 `.rd`，可与日常版并存），在「CarDeck 远程调试」入口填入地址与配对码即接入。接入后：
  - App 持续推送运行日志（批量回补 + 实时流；服务端按 seq 去重、环形保留 5000 行/设备）
  - 服务端可下发**白名单命令**：发起连接 / 断开连接 / 查询状态 / ping
  - 服务端可下发**悬浮窗提示**（App 上可拖动）
  - 服务端可推送**新 APK**：App 下载并校验 sha256 → 悬浮窗提示「安装」→ 先停会话释放虚拟屏（防止系统安装确认弹窗落到车机侧虚拟屏）→ PackageInstaller 发起；重装后首启动询问「继续进入调试模式？」并自动重连
- **会话稳定提示**（录制引导）：服务端盯实时日志——`RECORD 完成`/`隐形屏已启动` 判定会话激活，
  静默 N 秒（默认 10，`BRIDGE_STABLE_SECONDS`）无 `推流中止/Connection reset/SESSION 结束`
  即在手机悬浮窗提示**「连接已稳定——请现在开始复现问题」**（App 侧 RAW 转储与文件日志
  常开，保证录到的段落干净可归因）；断线自动复位、下轮再提示。`BRIDGE_AUTO_PROMPT=0` 关闭。
- **Agent 面**（MCP over stdio）：`bridge_status` / `logs_tail` / `logs_fetch` / `cmd` / `notify` /
  `prompt_reproduce`（手动下发复现引导）/ `watch_stability`（查看/配置稳定判定）/ `offer_apk`
- **文件面**：`GET /apk/<file>` 提供 APK 下载（重装闭环用）

## 快速开始

```bash
npm install
npm start
# 控制台输出：配对码：xxxxxx
```

手机端（remoteDebug 变体）→「CarDeck 远程调试」→ 填 `ws://<本机局域网IP>:8787` 与配对码 → 连接。

## 暴露到公网（内网穿透）

按场景选：

### 方案 A（国内跨地区，推荐）：frp + 国内轻量 VPS

Cloudflare 免费版无大陆节点（流量绕美西）且默认 QUIC 受 UDP QoS 限速，国内长连接不稳——
两端都在国内时 frp 直连 VPS 最快最稳（裸 IP 高位端口纯 TCP 转发，无需域名备案）。

```bash
# ── VPS 侧（阿里云/腾讯云轻量，几块钱/月）──
# 1) 下载 frp（https://github.com/fatedier/frp/releases，linux_amd64）
# 2) frps.toml：
#      bindPort = 7000
#      auth.token = "<强随机串>"
# 3) 启动（建议 systemd 常驻）：
./frps -c frps.toml
# 4) 安全组/防火墙放行 7000（frp 控制）与 8787（桥端口）

# ── 开发者电脑侧 ──
# frpc.toml：
#      serverAddr = "<VPS公网IP>"
#      serverPort = 7000
#      auth.token = "<同上强随机串>"
#      [[proxies]]
#      name = "cardeck-bridge"
#      type = "tcp"
#      localIP = "127.0.0.1"
#      localPort = 8787      # 必填：frp 0.7x 不默认继承 remotePort
#      remotePort = 8787
./frpc -c frpc.toml &
BRIDGE_PAIRING=<自定6位> PUBLIC_BASE=http://<VPS公网IP>:8787 npm start

# ── 手机侧（remoteDebug 变体）──
# 「CarDeck 远程调试」→ 地址填 ws://<VPS公网IP>:8787 → 配对码 → 连接
```

注意：明文 TCP（配对码只防误连，不防窃听）；调试日志含热点名/蓝牙地址，介意可换
自有域名 + HTTPS 网关终结 TLS 后再转发。

### 方案 B：国内穿透服务（免 VPS）

natapp / cpolar / 花生壳等，免费档有限速（传日志够用，推 APK 慢）。按其文档把本地
8787 映射为 tcp 隧道即可，手机端填 `ws://<映射地址>`。

### 方案 C：Cloudflare Tunnel（海外车友 / 已有域名）

```bash
cloudflared tunnel --protocol http2 --url http://127.0.0.1:8787
# 国内默认 QUIC 受 UDP QoS 限速，强制 http2 更稳；临时隧道（trycloudflare.com）线路质量差，
# 建议绑自有域名 + 优选 IP。手机端填 wss://<域名>；PUBLIC_BASE=https://<域名>
```

环境变量：`PORT`（默认 8787）、`PUBLIC_BASE`（APK 下载链接的公网基址）、`BRIDGE_PAIRING`（固定配对码，不设则随机生成）、`BRIDGE_AUTO_PROMPT`/`BRIDGE_STABLE_SECONDS`（稳定提示）。

## 接入 AI agent（MCP）

以 Claude/ZCode 类客户端的 MCP 配置为例：

```json
{
  "mcpServers": {
    "cardeck": {
      "command": "npm",
      "args": ["--prefix", "/path/to/cardeck-bridge", "run", "start"]
    }
  }
}
```

之后 agent 可直接：`bridge_status` → `logs_tail` 看车友日志 → `cmd(start_connection)` 复现问题 → `offer_apk` 推新包让用户一键重装。

## 安全边界

- 配对码一次性握手，明文错误码即断开；建议始终经 TLS（wss/cloudflared）或可信网络（局域网）
- 命令为**白名单**（连接控制与状态查询），不提供任意 shell/文件读写
- 日志含热点名/蓝牙地址等，仅用于排障；MCP 与 WS 同进程同机，不外发第三方
- remoteDebug 变体是独立包名（`.rd`），发布渠道请单独标注实验性质，勿作为默认版本分发

## License

MIT
