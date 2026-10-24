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
import { makeDelta } from "./deltadiff.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const PORT = Number(process.env.PORT ?? 8787);
const PUBLIC_BASE = (process.env.PUBLIC_BASE ?? `http://127.0.0.1:${PORT}`).replace(/\/$/, "");
const PAIRING = process.env.BRIDGE_PAIRING ?? String(crypto.randomInt(100000, 1000000));
const RING_CAP = 5000;
const AUTO_PROMPT = process.env.BRIDGE_AUTO_PROMPT !== "0";
const STABLE_SECONDS = Number(process.env.BRIDGE_STABLE_SECONDS ?? 10);
const SESSION_ACTIVE_RE = /RECORD 完成——会话已激活|MODE: 隐形屏 已启动|✓ VideoConfig/;
const SESSION_BAD_RE = /推流中止|Connection reset|SESSION 结束|SESSION 保活结束|EVENT: 读取结束|整轮 reset/;
const CMD_TIMEOUT_MS = 15000;
// 半开检测：对端路由切换/NAT 失效时 TCP 不发 FIN，server 侧 ws 永远「OPEN」。
// 25s 主动 ping，90s 无任何入站流量（含 pong/日志/命令应答）即 terminate——
// 设备随即收到 TCP 断开、立刻重连（2026-10-24 真机 incident：迟到的 close 事件
// 把新连接的 device.ws 清成 null，命令全拒而日志仍在流，拖了 3 分钟）。
const PEER_PING_MS = 25_000;
const PEER_DEAD_MS = 90_000;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "..", "public");
fs.mkdirSync(publicDir, { recursive: true });

// 差分基线索引：sha256 → 服务器上的 APK 路径。设备 hello 上报自己已安装 APK
// 的 sha256，offer 时若基线在库即生成差分包（典型 15MB → 0.1~2MB）。
const apkIndex = new Map<string, string>();
{
  const files = fs.readdirSync(publicDir).filter((f) => f.endsWith(".apk"));
  setImmediate(() => {
    for (const f of files) {
      try {
        const sha = crypto.createHash("sha256").update(fs.readFileSync(path.join(publicDir, f))).digest("hex");
        apkIndex.set(sha, path.join(publicDir, f));
      } catch {
        /* 文件消失等，跳过 */
      }
    }
    log(`差分基线库就绪：${apkIndex.size} 个 APK（${files.length} 个候选）`);
  });
}

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
  /** 最近一次入站流量时刻（半开检测：超过 PEER_DEAD_MS 视为死链） */
  lastSeen: number;
  /** 设备已安装 APK 的 sha256（hello 上报）——差分更新的基线选择依据 */
  baseSha256?: string;
  model?: string;
  appVersion?: string;
  lastSeq: number;
  ring: LogLine[];
  pending: Map<string, Pending>;
  since: number;
  /** 会话稳定判定（提示用户开始复现）：idle→active（会话激活）→stable（静默 N 秒）。 */
  watch: {
    auto: boolean;
    state: "idle" | "active" | "stable";
    activeAt: number;
    badSeen: boolean;
    prompted: boolean;
    stableSeconds: number;
  };
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
  watchFeed(device, text);
}

// ---- 会话稳定判定 → 提示用户开始复现 ----
// 录制（RAW 转储/文件日志）在 App 侧常开；这里判定的是「连接已建立且持续无断线」，
// 时机成熟时在手机悬浮窗提示用户开始复现问题——保证录到的段落干净、可归因。
function watchFeed(device: Device, text: string) {
  const w = device.watch;
  if (SESSION_BAD_RE.test(text)) {
    if (w.state !== "idle") log(`设备 ${device.deviceId} 会话中断（${text.slice(0, 60)}…）——稳定判定复位`);
    w.state = "idle";
    w.badSeen = true;
    w.prompted = false;
    return;
  }
  if (SESSION_ACTIVE_RE.test(text) && w.state === "idle") {
    w.state = "active";
    w.activeAt = Date.now();
    w.badSeen = false;
    log(`设备 ${device.deviceId} 会话已激活——静默 ${w.stableSeconds}s 后提示复现`);
  }
}

setInterval(() => {
  // 半开清扫：OPEN 但久无入站 → 先 ping 探测，仍无响应到死线即 terminate。
  // terminate 会让设备侧立刻收到 TCP 断开并重连，比等设备自己的读超时快得多。
  for (const device of devices.values()) {
    const ws = device.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) continue;
    const silent = Date.now() - device.lastSeen;
    if (silent >= PEER_DEAD_MS) {
      log(`设备 ${device.deviceId} ${Math.round(silent / 1000)}s 无入站流量——判定半开，强制断开等重连`);
      try {
        ws.terminate();
      } catch {
        /* close 事件兜底 */
      }
    } else if (silent >= PEER_PING_MS) {
      try {
        ws.ping();
      } catch {
        /* 下轮再试 */
      }
    }
  }
  for (const device of devices.values()) {
    const w = device.watch;
    if (w.state !== "active" || !w.auto || w.prompted) continue;
    if (Date.now() - w.activeAt >= w.stableSeconds * 1000) {
      w.state = "stable";
      w.prompted = true;
      const text = `连接已稳定（${w.stableSeconds}s 无断线）——请现在开始复现问题；完成后告知开发者即可（全程已录制）`;
      if (device.ws?.readyState === WebSocket.OPEN) {
        device.ws.send(JSON.stringify({ t: "notify", text }));
        log(`设备 ${device.deviceId} 稳定提示已下发（悬浮窗）`);
      }
    }
  }
}, 1000).unref();

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
      device =
        devices.get(id) ?? {
          ws: null,
          deviceId: id,
          lastSeen: Date.now(),
          lastSeq: 0,
          ring: [],
          pending: new Map(),
          since: 0,
          watch: { auto: AUTO_PROMPT, state: "idle", activeAt: 0, badSeen: false, prompted: false, stableSeconds: STABLE_SECONDS },
        };
      // 设备进程重启：App 端 seq 每进程从 1 计数，若桥仍留着上次的游标，
      // 去重逻辑（seq <= lastSeq 丢弃）会把新进程的全部日志静默丢掉——
      // 上报的 lastSeq 比桥记录的小即判定重启，清空游标与缓冲重新收。
      const reportedLast = Number(msg.lastSeq ?? 0);
      if (reportedLast < device.lastSeq) {
        log(`设备 ${id} 进程重启（lastSeq ${device.lastSeq} → ${reportedLast}），重置日志游标与缓冲`);
        device.lastSeq = 0;
        device.ring = [];
        device.since = 0;
      }
      device.watch.auto = AUTO_PROMPT; // 环境变量热生效
      // 同设备新连接接管：显式终止旧 socket，防止两个 socket 同时向一个
      // device 记录推日志、旧 socket 的迟到 close 事件又把新引用清掉
      if (device.ws && device.ws !== ws) {
        log(`设备 ${id} 旧连接被新连接接管——终止旧 socket`);
        try {
          device.ws.terminate();
        } catch {
          /* 已死则忽略 */
        }
      }
      device.ws = ws;
      device.lastSeen = Date.now();
      device.baseSha256 = msg.baseSha256 ? String(msg.baseSha256) : undefined;
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
    device.lastSeen = Date.now();
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
  ws.on("pong", () => {
    if (device) device.lastSeen = Date.now();
  });
  ws.on("close", () => {
    if (device) {
      log(`设备断开 ${device.deviceId}`);
      device.since = device.lastSeq; // 断线期间日志由重连后的全量回补补齐
      // 身份守卫：迟到 close 的旧 socket 不得清掉新连接的引用（否则命令
      // 全部「设备连接断开中」而日志仍在流——2026-10-24 实测 incident）
      if (device.ws === ws) device.ws = null;
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
  "prompt_reproduce",
  "在设备悬浮窗提示用户开始复现问题（稳定判定之外的手动触发；text 可自定义引导语）",
  { deviceId: z.string(), text: z.string().optional() },
  async ({ deviceId, text }) => {
    const device = deviceOrThrow(deviceId);
    send(device, {
      t: "notify",
      text: text ?? "请现在开始复现问题；完成后告知开发者即可（全程已录制）",
    });
    return { content: [{ type: "text" as const, text: "已下发悬浮窗提示" }] };
  },
);

mcp.tool(
  "watch_stability",
  "查看/配置会话稳定判定（auto 开关、静默窗口秒数；稳定后自动提示用户复现）",
  { deviceId: z.string(), auto: z.boolean().optional(), stableSeconds: z.number().int().min(3).max(120).optional() },
  async ({ deviceId, auto, stableSeconds }) => {
    const device = deviceOrThrow(deviceId);
    if (auto !== undefined) device.watch.auto = auto;
    if (stableSeconds !== undefined) device.watch.stableSeconds = stableSeconds;
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            auto: device.watch.auto,
            state: device.watch.state,
            stableSeconds: device.watch.stableSeconds,
            prompted: device.watch.prompted,
          }),
        },
      ],
    };
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
    apkIndex.set(sha256, path.join(publicDir, name));
    const url = `${PUBLIC_BASE}/apk/${name}`;
    // 差分优先：设备基线在库里 → 生成块差分包，显著省流量（回退全量始终随附）
    let delta: { url: string; sha256: string; baseSha256: string; sizeKB: number } | undefined;
    const baseSha = device.baseSha256;
    const basePath = baseSha ? apkIndex.get(baseSha) : undefined;
    if (basePath && baseSha !== sha256) {
      const patch = makeDelta(fs.readFileSync(basePath), bytes);
      // 收益不足（> 全量 60%）就不值得一次基线校验的风险
      if (patch.length < bytes.length * 0.6) {
        const patchName = `cardeck-${version}-${Date.now()}.bspatch`;
        fs.writeFileSync(path.join(publicDir, patchName), patch);
        delta = {
          url: `${PUBLIC_BASE}/apk/${patchName}`,
          sha256: crypto.createHash("sha256").update(patch).digest("hex"),
          baseSha256: baseSha!,
          sizeKB: Math.round(patch.length / 1024),
        };
        log(`设备 ${deviceId} 差分包 ${delta.sizeKB}KB（全量 ${Math.round(bytes.length / 1024)}KB，基线 ${baseSha!.slice(0, 8)}）`);
      }
    }
    send(device, { t: "apk.offer", url, sha256, version, delta });
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify({
            url,
            sha256,
            sizeMB: Math.round(bytes.length / 1024 / 1024),
            delta: delta ? `${delta.sizeKB}KB（基线 ${delta.baseSha256.slice(0, 8)}）` : "无基线，全量",
          }),
        },
      ],
    };
  },
);

const transport = new StdioServerTransport();
await mcp.connect(transport);
log("MCP（stdio）已就绪");
