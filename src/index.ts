/**
 * CarDeck 远程调试桥（单进程双面）：
 *  - 设备面：WebSocket（默认 :8787，任意路径），App 端用 6 位配对码接入；
 *  - Agent 面：MCP（stdio），提供 devices/logs/cmd/notify/apk 工具；
 *  - 文件面：GET /apk/<file> 下发新构建的 APK（重装闭环）。
 *
 * 启动：npm start
 * 环境变量：PORT=8787  PUBLIC_BASE=http://127.0.0.1:8787  BRIDGE_PAIRING=（不设则随机）
 * 内网穿透：cloudflared tunnel --url http://127.0.0.1:8787（wss 自动可用）
 *          或 frp 转发 TCP；agent 走本机 stdio 不需要穿透。
 */
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer, WebSocket } from "ws";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const PORT = Number(process.env.PORT ?? 8787);
const PUBLIC_BASE = (process.env.PUBLIC_BASE ?? `http://127.0.0.1:${PORT}`).replace(/\/$/, "");
const PAIRING = process.env.BRIDGE_PAIRING ?? String(crypto.randomInt(100000, 1000000));
const RING_CAP = 5000;
const CMD_TIMEOUT_MS = 15000;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "..", "public");
fs.mkdirSync(publicDir, { recursive: true });

interface LogLine {
  seq: number;
  text: string;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
}

interface Device {
  ws: WebSocket | null;
  deviceId: string;
  model?: string;
  appVersion?: string;
  lastSeq: number;
  ring: LogLine[];
  pending: Map<string, Pending>;
  since: number;
}

const devices = new Map<string, Device>();
const sockets = new Map<WebSocket, Device>();

function log(...args: unknown[]) {
  console.log("[bridge]", new Date().toISOString().slice(11, 19), ...args);
}

function pushLine(device: Device, seq: number, text: string) {
  if (seq <= 0) return;
  if (seq <= device.lastSeq) return; // 重复/乱序：按 seq 去重
  device.lastSeq = seq;
  device.ring.push({ seq, text });
  if (device.ring.length > RING_CAP) device.ring.splice(0, device.ring.length - RING_CAP);
}

function deviceOrThrow(deviceId: string): Device {
  const device = devices.get(deviceId);
  if (!device) {
    const known = [...devices.keys()].join(", ") || "无";
    throw new Error(`设备 ${deviceId} 未连接；当前在线：${known}`);
  }
  return device;
}

function send(device: Device, obj: Record<string, unknown>) {
  if (device.ws?.readyState !== WebSocket.OPEN) throw new Error("设备连接断开中");
  device.ws.send(JSON.stringify(obj));
}

function roundTrip(device: Device, name: string, args: Record<string, unknown> = {}): Promise<unknown> {
  const id = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      device.pending.delete(id);
      reject(new Error(`命令 ${name} 超时（${CMD_TIMEOUT_MS}ms）`));
    }, CMD_TIMEOUT_MS);
    device.pending.set(id, { resolve, reject, timer });
    try {
      send(device, { t: "cmd", id, name, args });
    } catch (error) {
      clearTimeout(timer);
      device.pending.delete(id);
      reject(error as Error);
    }
  });
}

// ---- HTTP + WS ----

const server = http.createServer((req, res) => {
  if (req.url?.startsWith("/apk/")) {
    const file = path.basename(req.url.slice(5));
    const full = path.join(publicDir, file);
    if (!fs.existsSync(full)) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/vnd.android.package-archive" });
    fs.createReadStream(full).pipe(res);
    return;
  }
  res.writeHead(200).end("cardeck-bridge\n");
});

const wss = new WebSocketServer({ server });

wss.on("connection", (ws: WebSocket) => {
  let device: Device | null = null;
  ws.on("message", (raw) => {
    let msg: any;
    try {
      msg = JSON.parse(String(raw));
    } catch {
      return;
    }
    if (msg.t === "hello") {
      if (String(msg.code ?? "") !== PAIRING) {
        ws.send(JSON.stringify({ t: "welcome", ok: false, error: "配对码错误" }));
        ws.close();
        return;
      }
      const id = String(msg.deviceId ?? "unknown");
      device = devices.get(id) ?? { ws: null, deviceId: id, lastSeq: 0, ring: [], pending: new Map(), since: 0 };
      device.ws = ws;
      device.model = msg.deviceModel;
      device.appVersion = msg.appVersion;
      devices.set(id, device);
      sockets.set(ws, device);
      ws.send(JSON.stringify({ t: "welcome", ok: true, pairedAt: Date.now() }));
      log(`设备接入 ${id}（${device.model ?? "?"} v${device.appVersion ?? "?"}），请求日志回补 since=${device.since}`);
      if (device.since > 0) ws.send(JSON.stringify({ t: "log.sync", since: device.since }));
      return;
    }
    if (!device) return;
    switch (msg.t) {
      case "log.batch": {
        const lines: any[] = msg.lines ?? [];
        for (const line of lines) pushLine(device, Number(line.seq), String(line.text ?? ""));
        break;
      }
      case "cmd.result": {
        const pending = device.pending.get(String(msg.id));
        if (pending) {
          clearTimeout(pending.timer);
          device.pending.delete(String(msg.id));
          pending.resolve({ ok: Boolean(msg.ok), detail: msg.detail });
        }
        break;
      }
      case "status":
        log(`设备 ${device.deviceId} 状态：${msg.state}`);
        break;
      case "pong":
        break;
    }
  });
  ws.on("close", () => {
    if (device) {
      log(`设备断开 ${device.deviceId}`);
      device.since = device.lastSeq; // 断线期间日志由重连后的全量回补补齐
      device.ws = null;
      for (const pending of device.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error("设备连接断开"));
      }
      device.pending.clear();
      if (sockets.get(ws) === device && !device.ws) sockets.delete(ws);
    }
  });
});

server.listen(PORT, () => {
  log(`调试桥就绪 :${PORT}（公网基址 ${PUBLIC_BASE}）`);
  log(`配对码：${PAIRING}`);
});

// ---- MCP（agent 面） ----

const mcp = new McpServer(
  { name: "cardeck-bridge", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

mcp.tool(
  "bridge_status",
  "桥状态：配对码与在线设备列表",
  {},
  async () => ({
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            pairingCode: PAIRING,
            publicBase: PUBLIC_BASE,
            devices: [...devices.values()].map((d) => ({
              deviceId: d.deviceId,
              model: d.model,
              appVersion: d.appVersion,
              online: Boolean(d.ws),
              lastSeq: d.lastSeq,
            })),
          },
          null,
          2,
        ),
      },
    ],
  }),
);

mcp.tool(
  "logs_tail",
  "取设备最近 N 行日志",
  { deviceId: z.string(), lines: z.number().int().min(1).max(2000).default(200) },
  async ({ deviceId, lines }) => {
    const device = deviceOrThrow(deviceId);
    const tail = device.ring.slice(-lines);
    return { content: [{ type: "text" as const, text: tail.map((l) => l.text).join("\n") || "（无日志）" }] };
  },
);

mcp.tool(
  "logs_fetch",
  "取设备 sinceSeq 之后的日志（增量拉取）",
  { deviceId: z.string(), sinceSeq: z.number().int().default(0), max: z.number().int().min(1).max(5000).default(2000) },
  async ({ deviceId, sinceSeq, max }) => {
    const device = deviceOrThrow(deviceId);
    const lines = device.ring.filter((l) => l.seq > sinceSeq).slice(0, max);
    return { content: [{ type: "text" as const, text: lines.map((l) => l.text).join("\n") || "（无新日志）" }] };
  },
);

mcp.tool(
  "cmd",
  "向设备下发白名单命令（start_connection/stop_connection/get_state/ping）",
  { deviceId: z.string(), name: z.string(), args: z.record(z.string(), z.unknown()).optional() },
  async ({ deviceId, name, args }) => {
    const device = deviceOrThrow(deviceId);
    const result = (await roundTrip(device, name, args ?? {})) as Record<string, unknown>;
    return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
  },
);

mcp.tool(
  "notify",
  "在设备悬浮窗上显示提示文字",
  { deviceId: z.string(), text: z.string() },
  async ({ deviceId, text }) => {
    const device = deviceOrThrow(deviceId);
    send(device, { t: "notify", text });
    return { content: [{ type: "text" as const, text: "已下发" }] };
  },
);

mcp.tool(
  "offer_apk",
  "向设备推送新 APK（复制到 public/ 并下发安装提示；filePath 为本地 APK 绝对路径）",
  { deviceId: z.string(), filePath: z.string(), version: z.string().default("debug") },
  async ({ deviceId, filePath, version }) => {
    const device = deviceOrThrow(deviceId);
    if (!fs.existsSync(filePath)) throw new Error(`文件不存在：${filePath}`);
    const bytes = fs.readFileSync(filePath);
    const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
    const name = `cardeck-${version}-${Date.now()}.apk`;
    fs.writeFileSync(path.join(publicDir, name), bytes);
    const url = `${PUBLIC_BASE}/apk/${name}`;
    send(device, { t: "apk.offer", url, sha256, version });
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({ url, sha256, sizeMB: Math.round(bytes.length / 1024 / 1024) }),
        },
      ],
    };
  },
);

const transport = new StdioServerTransport();
await mcp.connect(transport);
log("MCP（stdio）已就绪");
