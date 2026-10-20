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
- **Agent 面**（MCP over stdio）：`bridge_status` / `logs_tail` / `logs_fetch` / `cmd` / `notify` / `offer_apk`
- **文件面**：`GET /apk/<file>` 提供 APK 下载（重装闭环用）

## 快速开始

```bash
npm install
npm start
# 控制台输出：配对码：xxxxxx
```

手机端（remoteDebug 变体）→「CarDeck 远程调试」→ 填 `ws://<本机局域网IP>:8787` 与配对码 → 连接。

## 暴露到公网（内网穿透）

任选其一：

```bash
# 方案 A：Cloudflare Tunnel（免费、自带 TLS 域名，wss 直接可用）
cloudflared tunnel --url http://127.0.0.1:8787
# 手机端填 wss://<分配的域名>；并 export PUBLIC_BASE=https://<域名> 后重启服务（APK 下载链接要用公网基址）

# 方案 B：frp（已有 VPS 时，转发 TCP 即可）
# frpc.toml: [[proxies]] ... remotePort = 8788
# 手机端填 ws://<VPS>:8788；PUBLIC_BASE=http://<VPS>:8788
```

环境变量：`PORT`（默认 8787）、`PUBLIC_BASE`（APK 下载链接的公网基址）、`BRIDGE_PAIRING`（固定配对码，不设则随机生成）。

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
