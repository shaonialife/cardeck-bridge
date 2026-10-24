/**
 * 字节级块差分（rsync 式）：老 APK 与新 APK 大部分字节相同（改动集中在 dex/arsc
 * 局部），按块哈希匹配生成「COPY 老文件区间 / LITERAL 新字节」指令流，设备端
 * 拼装出与目标逐字节一致的文件（sha256 兜底），典型压到全量的 1%~10%。
 *
 * 选型理由：不引 bsdiff/bzip2（设备端要带解压库、服务端要装工具），块匹配
 * 纯 Buffer 实现两端各 ~100 行；补丁体积对「测试构建」场景（小改码）足够好。
 *
 * 补丁二进制格式（两端硬约定，勿单独改动）：
 *   "CDDELTA1"          8B magic
 *   targetLen           u64 LE
 *   targetSha256        32B raw
 *   baseLen             u64 LE
 *   baseSha256          32B raw
 *   ops（直到 EOF）：
 *     0x01 COPY    u64 oldOffset, u64 len      （从基线文件复制）
 *     0x02 LITERAL u64 len, len bytes          （补丁内联字节）
 */
import crypto from "node:crypto";

const MAGIC = "CDDELTA1";
const BLOCK = 4096;

/** 4KB 块的 FNV-1a（非滚动，匹配命中后成块推进，O(n) 足够） */
function fnv1a(buf: Buffer, start: number, len: number): number {
  let h = 0x811c9dc5;
  const end = start + len;
  for (let i = start; i < end; i++) {
    h ^= buf[i];
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

interface Op {
  copy: boolean;
  a: number; // copy: oldOffset / literal: len
  b?: number; // copy: len
  lit?: Buffer;
}

export function makeDelta(base: Buffer, target: Buffer): Buffer {
  // 1. 老文件按块建索引（hash → 偏移列表）
  const index = new Map<number, number[]>();
  for (let off = 0; off + BLOCK <= base.length; off += BLOCK) {
    const h = fnv1a(base, off, BLOCK);
    const list = index.get(h);
    if (list) list.push(off);
    else index.set(h, [off]);
  }

  // 2. 扫描目标文件：窗口哈希命中 → 字节校验 → 成块贪心延伸
  const ops: Op[] = [];
  let lit = Buffer.alloc(0);
  let i = 0;
  const flushLit = () => {
    if (lit.length > 0) {
      ops.push({ copy: false, a: lit.length, lit });
      lit = Buffer.alloc(0);
    }
  };
  while (i < target.length) {
    const remain = target.length - i;
    const win = Math.min(BLOCK, remain);
    if (win < BLOCK) {
      // 尾部不足一块：全为字面量
      lit = Buffer.concat([lit, target.subarray(i)]);
      i = target.length;
      break;
    }
    const h = fnv1a(target, i, BLOCK);
    const candidates = index.get(h);
    let matched = false;
    if (candidates) {
      for (const oldOff of candidates) {
        if (base.compare(target, i, i + BLOCK, oldOff, oldOff + BLOCK) !== 0) continue;
        // 命中：向后成块贪心延伸
        let len = BLOCK;
        while (
          i + len + BLOCK <= target.length &&
          oldOff + len + BLOCK <= base.length &&
          base.compare(target, i + len, i + len + BLOCK, oldOff + len, oldOff + len + BLOCK) === 0
        ) {
          len += BLOCK;
        }
        flushLit();
        ops.push({ copy: true, a: oldOff, b: len });
        i += len;
        matched = true;
        break;
      }
    }
    if (!matched) {
      // 逐字节推进字面量（每次拼 64KB 批，避免 Buffer.concat 退化）
      const chunk = Math.min(remain, 65536);
      lit = Buffer.concat([lit, target.subarray(i, i + chunk)]);
      i += chunk;
    }
  }
  flushLit();

  // 3. 序列化。头部共 88B（8 magic + 8 len + 32 sha + 8 len + 32 sha）；
  // u64 一律大端——设备端 Kotlin RandomAccessFile.readLong 只读大端
  // （2026-10-24 实测：LE+72B 截断两个 bug 叠加，差分首跳静默回退全量）。
  const targetSha = crypto.createHash("sha256").update(target).digest();
  const baseSha = crypto.createHash("sha256").update(base).digest();
  const head = Buffer.alloc(8 + 8 + 32 + 8 + 32);
  head.write(MAGIC, 0, 8, "ascii");
  head.writeBigUInt64BE(BigInt(target.length), 8);
  targetSha.copy(head, 16);
  head.writeBigUInt64BE(BigInt(base.length), 48);
  baseSha.copy(head, 56);
  const opBufs: Buffer[] = [head];
  for (const op of ops) {
    if (op.copy) {
      const b = Buffer.alloc(17);
      b.writeUInt8(0x01, 0);
      b.writeBigUInt64BE(BigInt(op.a), 1);
      b.writeBigUInt64BE(BigInt(op.b ?? 0), 9);
      opBufs.push(b);
    } else {
      const b = Buffer.alloc(9);
      b.writeUInt8(0x02, 0);
      b.writeBigUInt64BE(BigInt(op.a), 1);
      opBufs.push(b, op.lit!);
    }
  }
  return Buffer.concat(opBufs);
}
