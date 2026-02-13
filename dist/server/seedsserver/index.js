// ============================================================
// BTR (Buturi Coin) - シードノード メインサーバー
// ============================================================
import net from 'net';
import { WebSocketServer } from 'ws';
import { createServer as createHTTPSServer } from 'https';
import { createServer as createHTTPServer } from 'http';
import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { PacketBuffer, sendTCP, sendWS } from './protocol.js';
import { TrustManager } from './trust.js';
import { RandomManager } from './random.js';
class Ed25519 {
    // ── 定数 ──
    static p = 2n ** 255n - 19n;
    static L = 2n ** 252n + 27742317777372353535851937790883648493n;
    static d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
    static SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
    static Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
    static Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
    static G_EXT = [
        Ed25519.Gx,
        Ed25519.Gy,
        1n,
        (Ed25519.Gx * Ed25519.Gy) % Ed25519.p,
    ];
    static ED25519_OID = new Uint8Array([
        0x06, 0x03, 0x2b, 0x65, 0x70,
    ]);
    // ── Fixed-window テーブル (遅延初期化, w=4) ──
    static W = 4;
    static _gTable = null;
    static get gTable() {
        if (!this._gTable) {
            const size = 1 << this.W;
            const t = new Array(size);
            t[0] = [0n, 1n, 1n, 0n];
            t[1] = this.G_EXT;
            for (let i = 2; i < size; i++)
                t[i] = this.extAdd(t[i - 1], this.G_EXT);
            this._gTable = t;
        }
        return this._gTable;
    }
    // ━━━━━━━━━━━━━ 基本演算 ━━━━━━━━━━━━━
    static mod(n, m) {
        const r = n % m;
        return r < 0n ? r + m : r;
    }
    static modInv(a, m) {
        let r0 = m, r1 = a < 0n ? ((a % m) + m) % m : a % m;
        let x0 = 0n, x1 = 1n;
        while (r1 !== 0n) {
            const q = r0 / r1;
            [r0, r1] = [r1, r0 - q * r1];
            [x0, x1] = [x1, x0 - q * x1];
        }
        return x0 < 0n ? x0 + m : x0;
    }
    static modPow(base, exp, m) {
        let result = 1n;
        base = ((base % m) + m) % m;
        while (exp > 0n) {
            if (exp & 1n)
                result = (result * base) % m;
            base = (base * base) % m;
            exp >>= 1n;
        }
        return result;
    }
    // ━━━━━━━━━━━━━ 楕円曲線演算 (Extended 座標) ━━━━━━━━━━━━━
    static extAdd(p1, p2) {
        const P = this.p;
        const [X1, Y1, Z1, T1] = p1;
        const [X2, Y2, Z2, T2] = p2;
        const A = this.mod(X1 * X2, P);
        const B = this.mod(Y1 * Y2, P);
        const C = this.mod(this.mod(this.d * T1, P) * T2, P);
        const D = this.mod(Z1 * Z2, P);
        const E = this.mod(this.mod((X1 + Y1) * (X2 + Y2), P) - A - B, P);
        const F = this.mod(D - C, P);
        const G = this.mod(D + C, P);
        const H = this.mod(B + A, P);
        return [
            this.mod(E * F, P),
            this.mod(G * H, P),
            this.mod(F * G, P),
            this.mod(E * H, P),
        ];
    }
    static extDouble(pt) {
        const P = this.p;
        const [X1, Y1, Z1] = pt;
        const A = this.mod(X1 * X1, P);
        const B = this.mod(Y1 * Y1, P);
        const C = this.mod(2n * ((Z1 * Z1) % P), P);
        const D = this.mod(P - A, P);
        const xpy = this.mod(X1 + Y1, P);
        const E = this.mod(xpy * xpy - A - B, P);
        const G = this.mod(D + B, P);
        const F = this.mod(G - C, P);
        const H = this.mod(D - B, P);
        return [
            this.mod(E * F, P),
            this.mod(G * H, P),
            this.mod(F * G, P),
            this.mod(E * H, P),
        ];
    }
    static extToAffine(pt) {
        const [X, Y, Z] = pt;
        if (Z === 0n)
            return [0n, 1n];
        const zi = this.modInv(Z, this.p);
        return [this.mod(X * zi, this.p), this.mod(Y * zi, this.p)];
    }
    // ━━━━━━━━━━━━━ スカラー乗算 ━━━━━━━━━━━━━
    static scalarMultG(k) {
        const table = this.gTable;
        const mask = BigInt((1 << this.W) - 1);
        const steps = 64;
        let R = [0n, 1n, 1n, 0n];
        for (let i = steps - 1; i >= 0; i--) {
            for (let j = 0; j < this.W; j++)
                R = this.extDouble(R);
            const idx = Number((k >> BigInt(i * this.W)) & mask);
            if (idx !== 0)
                R = this.extAdd(R, table[idx]);
        }
        return R;
    }
    static scalarMult(k, point) {
        let R = [0n, 1n, 1n, 0n];
        let Q = point;
        while (k > 0n) {
            if (k & 1n)
                R = this.extAdd(R, Q);
            Q = this.extDouble(Q);
            k >>= 1n;
        }
        return R;
    }
    static shamirMult(s, k, A) {
        const GA = this.extAdd(this.G_EXT, A);
        let R = [0n, 1n, 1n, 0n];
        for (let i = 255; i >= 0; i--) {
            R = this.extDouble(R);
            const sb = (s >> BigInt(i)) & 1n;
            const kb = (k >> BigInt(i)) & 1n;
            if (sb && kb)
                R = this.extAdd(R, GA);
            else if (sb)
                R = this.extAdd(R, this.G_EXT);
            else if (kb)
                R = this.extAdd(R, A);
        }
        return R;
    }
    // ━━━━━━━━━━━━━ エンコーディング ━━━━━━━━━━━━━
    static pointToBytes(point) {
        const [x, y] = point;
        const out = new Uint8Array(32);
        for (let i = 0; i < 32; i++)
            out[i] = Number((y >> BigInt(i * 8)) & 0xffn);
        if (x & 1n)
            out[31] |= 0x80;
        return out;
    }
    static bytesToPoint(bytes) {
        if (bytes.length !== 32)
            throw new Error("Invalid point encoding");
        let y = 0n;
        for (let i = 0; i < 32; i++)
            y |= BigInt(bytes[i] & (i === 31 ? 0x7f : 0xff)) << BigInt(i * 8);
        if (y >= this.p)
            throw new Error("y coordinate out of range");
        const x_sign = (bytes[31] & 0x80) !== 0;
        const P = this.p;
        const y2 = (y * y) % P;
        const num = this.mod(y2 - 1n, P);
        const den = this.mod(this.d * y2 + 1n, P);
        const x2 = (num * this.modInv(den, P)) % P;
        if (x2 === 0n) {
            if (x_sign)
                throw new Error("Invalid point encoding");
            return [0n, y, 1n, 0n];
        }
        let x = this.modPow(x2, (P + 3n) / 8n, P);
        if ((x * x) % P !== this.mod(x2, P)) {
            x = (x * this.SQRT_M1) % P;
            if ((x * x) % P !== this.mod(x2, P))
                throw new Error("Invalid point: no square root");
        }
        if ((x & 1n) !== (x_sign ? 1n : 0n))
            x = P - x;
        const xc = (x * x) % P;
        const yc = (y * y) % P;
        if (this.mod(yc - xc, P) !==
            this.mod(1n + ((this.d * ((xc * yc) % P)) % P), P))
            throw new Error("Point is not on curve");
        return [x, y, 1n, (x * y) % P];
    }
    static bigIntToBytes(n, len) {
        const out = new Uint8Array(len);
        for (let i = 0; i < len; i++)
            out[i] = Number((n >> BigInt(i * 8)) & 0xffn);
        return out;
    }
    static bytesToBigInt(bytes) {
        let r = 0n;
        for (let i = bytes.length - 1; i >= 0; i--)
            r = (r << 8n) | BigInt(bytes[i]);
        return r;
    }
    // ━━━━━━━━━━━━━ ヘルパー ━━━━━━━━━━━━━
    static async sha512(data) {
        return new Uint8Array(await crypto.subtle.digest("SHA-512", data.buffer));
    }
    static concat(...arrays) {
        let len = 0;
        for (const a of arrays)
            len += a.length;
        const out = new Uint8Array(len);
        let off = 0;
        for (const a of arrays) {
            out.set(a, off);
            off += a.length;
        }
        return out;
    }
    static clamp(s) {
        return (s & ((1n << 255n) - 1n) & ~7n) | (1n << 254n);
    }
    // ━━━━━━━━━━━━━ DERエンコード ━━━━━━━━━━━━━
    static encodeDerLength(len) {
        if (len <= 127)
            return new Uint8Array([len]);
        let bytesNeeded;
        if (len >= 0x1000000)
            bytesNeeded = 4;
        else if (len >= 0x10000)
            bytesNeeded = 3;
        else if (len >= 0x100)
            bytesNeeded = 2;
        else
            bytesNeeded = 1;
        const res = new Uint8Array(bytesNeeded + 1);
        res[0] = 0x80 | bytesNeeded;
        let t = len;
        for (let i = bytesNeeded; i >= 1; i--) {
            res[i] = t & 0xff;
            t >>= 8;
        }
        return res;
    }
    static encodeDerSequence(elements) {
        let total = 0;
        for (const el of elements)
            total += el.length;
        const body = new Uint8Array(total);
        let off = 0;
        for (const el of elements) {
            body.set(el, off);
            off += el.length;
        }
        const len = this.encodeDerLength(body.length);
        const res = new Uint8Array(1 + len.length + body.length);
        res[0] = 0x30;
        res.set(len, 1);
        res.set(body, 1 + len.length);
        return res;
    }
    static encodeDerOctetString(bytes) {
        const len = this.encodeDerLength(bytes.length);
        const res = new Uint8Array(1 + len.length + bytes.length);
        res[0] = 0x04;
        res.set(len, 1);
        res.set(bytes, 1 + len.length);
        return res;
    }
    static encodeDerBitString(bytes) {
        const len = this.encodeDerLength(bytes.length + 1);
        const res = new Uint8Array(1 + len.length + 1 + bytes.length);
        res[0] = 0x03;
        res.set(len, 1);
        res[1 + len.length] = 0x00;
        res.set(bytes, 1 + len.length + 1);
        return res;
    }
    // ━━━━━━━━━━━━━ DERデコード ━━━━━━━━━━━━━
    static parseDerTLV(data, offset) {
        const tag = data[offset++];
        const first = data[offset++];
        let length;
        if (first <= 127) {
            length = first;
        }
        else {
            const n = first & 0x7f;
            length = 0;
            for (let i = 0; i < n; i++)
                length = (length << 8) | data[offset++];
        }
        return {
            tag,
            value: data.subarray(offset, offset + length),
            end: offset + length,
        };
    }
    static parseDerChildren(data) {
        const children = [];
        let offset = 0;
        while (offset < data.length) {
            const tlv = this.parseDerTLV(data, offset);
            children.push({ tag: tlv.tag, value: tlv.value });
            offset = tlv.end;
        }
        return children;
    }
    static unwrapDer(data, expectedTag) {
        const tlv = this.parseDerTLV(data, 0);
        if (tlv.tag !== expectedTag)
            throw new Error(`DER: expected 0x${expectedTag.toString(16)}, got 0x${tlv.tag.toString(16)}`);
        return tlv.value;
    }
    static checkEd25519OID(algSeqValue) {
        const children = this.parseDerChildren(algSeqValue);
        if (children.length === 0 || children[0].tag !== 0x06)
            throw new Error("Expected OID");
        const oid = children[0].value;
        if (oid.length !== 3 ||
            oid[0] !== 0x2b ||
            oid[1] !== 0x65 ||
            oid[2] !== 0x70)
            throw new Error("OID is not Ed25519 (1.3.101.112)");
    }
    // ━━━━━━━━━━━━━ Base64 / PEM ━━━━━━━━━━━━━
    static base64Encode(data) {
        if (typeof Buffer !== "undefined")
            return Buffer.from(data).toString("base64");
        let s = "";
        for (const b of data)
            s += String.fromCharCode(b);
        return btoa(s);
    }
    static base64Decode(str) {
        if (typeof Buffer !== "undefined")
            return new Uint8Array(Buffer.from(str, "base64"));
        const bin = atob(str);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++)
            out[i] = bin.charCodeAt(i);
        return out;
    }
    static pemDecode(pem) {
        return this.base64Decode(pem.replace(/-----.*?-----|\s+/g, ""));
    }
    static pemEncode(der, label) {
        const b64 = this.base64Encode(der);
        const lines = [];
        for (let i = 0; i < b64.length; i += 64)
            lines.push(b64.substring(i, i + 64));
        return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
    }
    // ━━━━━━━━━━━━━ 公開 API (署名) ━━━━━━━━━━━━━
    static async getPublicKey(privateKey) {
        if (privateKey.length !== 32)
            throw new Error("Private key must be 32 bytes");
        const h = await this.sha512(privateKey);
        const s = this.clamp(this.bytesToBigInt(h.subarray(0, 32)));
        return this.pointToBytes(this.extToAffine(this.scalarMultG(s)));
    }
    static async sign(message, privateKey) {
        if (privateKey.length !== 32)
            throw new Error("Private key must be 32 bytes");
        const h = await this.sha512(privateKey);
        const s = this.clamp(this.bytesToBigInt(h.subarray(0, 32)));
        const pubBytes = this.pointToBytes(this.extToAffine(this.scalarMultG(s)));
        const rHash = await this.sha512(this.concat(h.subarray(32, 64), message));
        const r = this.mod(this.bytesToBigInt(rHash), this.L);
        const RBytes = this.pointToBytes(this.extToAffine(this.scalarMultG(r)));
        const kHash = await this.sha512(this.concat(RBytes, pubBytes, message));
        const k = this.mod(this.bytesToBigInt(kHash), this.L);
        const S = this.mod(r + k * s, this.L);
        return this.concat(RBytes, this.bigIntToBytes(S, 32));
    }
    static async verify(signature, message, publicKey) {
        if (signature.length !== 64 || publicKey.length !== 32)
            return false;
        try {
            const RBytes = signature.subarray(0, 32);
            const S = this.bytesToBigInt(signature.subarray(32, 64));
            if (S >= this.L)
                return false;
            const R = this.bytesToPoint(RBytes);
            const A = this.bytesToPoint(publicKey);
            const kHash = await this.sha512(this.concat(RBytes, publicKey, message));
            const k = this.mod(this.bytesToBigInt(kHash), this.L);
            const result = this.shamirMult(S, this.mod(this.L - k, this.L), A);
            const [rx, ry] = this.extToAffine(result);
            const [r0x, r0y] = this.extToAffine(R);
            return rx === r0x && ry === r0y;
        }
        catch {
            return false;
        }
    }
    // ━━━━━━━━━━━━━ 公開 API (PEM) ━━━━━━━━━━━━━
    static privateKeyToPem(raw) {
        if (raw.length !== 32)
            throw new Error("Ed25519 private key must be 32 bytes");
        const version = new Uint8Array([0x02, 0x01, 0x00]);
        const algId = this.encodeDerSequence([this.ED25519_OID]);
        const keyOctet = this.encodeDerOctetString(this.encodeDerOctetString(raw));
        return this.pemEncode(this.encodeDerSequence([version, algId, keyOctet]), "PRIVATE KEY");
    }
    static pemToPrivateKey(pem) {
        const outer = this.unwrapDer(this.pemDecode(pem), 0x30);
        const children = this.parseDerChildren(outer);
        if (children.length < 3)
            throw new Error("Invalid PKCS#8");
        this.checkEd25519OID(children[1].value);
        if (children[2].tag !== 0x04)
            throw new Error("Expected OCTET STRING");
        const inner = this.unwrapDer(children[2].value, 0x04);
        if (inner.length !== 32)
            throw new Error(`Expected 32 bytes, got ${inner.length}`);
        return new Uint8Array(inner);
    }
    static publicKeyToPem(raw) {
        if (raw.length !== 32)
            throw new Error("Ed25519 public key must be 32 bytes");
        const algId = this.encodeDerSequence([this.ED25519_OID]);
        const bitStr = this.encodeDerBitString(raw);
        return this.pemEncode(this.encodeDerSequence([algId, bitStr]), "PUBLIC KEY");
    }
    static pemToPublicKey(pem) {
        const outer = this.unwrapDer(this.pemDecode(pem), 0x30);
        const children = this.parseDerChildren(outer);
        if (children.length < 2)
            throw new Error("Invalid SPKI");
        this.checkEd25519OID(children[0].value);
        if (children[1].tag !== 0x03)
            throw new Error("Expected BIT STRING");
        const bits = children[1].value;
        if (bits[0] !== 0x00)
            throw new Error("BIT STRING unused bits must be 0");
        const pub = bits.subarray(1);
        if (pub.length !== 32)
            throw new Error(`Expected 32 bytes, got ${pub.length}`);
        return new Uint8Array(pub);
    }
}
// ============================================================
// 設定
// ============================================================
const CONFIG = {
    ROOT_PUBLIC_KEY: '04920517f44339fed12ebbc8f2c0ae93a0c2bfa4a9ef4bfee1c6f12b452eab70',
    TCP_PORT: 5000,
    WSS_PORT: 443,
    WSS_DEV_PORT: 8443,
    SEED_PORT: 40000,
    HEARTBEAT_INTERVAL: 5000,
    HEARTBEAT_TIMEOUT: 15000,
    RANDOM_INTERVAL: 60 * 60 * 1000,
    RANDOM_TIMEOUT: 10000,
    SSL_CERT: '/etc/letsencrypt/live/shudo-physics.f5.si/fullchain.pem',
    SSL_KEY: '/etc/letsencrypt/live/shudo-physics.f5.si/privkey.pem',
    SEEDS_PATH: './seeds.json',
    SEEDS_CDN: 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/seeds.json',
};
const fullNodes = new Map();
const clients = new Map();
const seedPeers = new Map();
let trustManager;
let randomManager;
let latestNodeCode = null;
let myPriority = 1;
let isPrimary = true;
let nodeIdCounter = 0;
let clientIdCounter = 0;
function generateId(prefix) {
    const counter = prefix === 'node' ? ++nodeIdCounter : ++clientIdCounter;
    return `${prefix}_${Date.now()}_${counter}`;
}
function log(category, message) {
    const time = new Date().toISOString().slice(11, 19);
    console.log(`[${time}][${category}] ${message}`);
}
// ============================================================
// ヘルパー関数
// ============================================================
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
// ============================================================
// seeds.json & シードノード間接続
// ============================================================
function loadSeeds() {
    try {
        if (fs.existsSync(CONFIG.SEEDS_PATH)) {
            const data = JSON.parse(fs.readFileSync(CONFIG.SEEDS_PATH, 'utf-8'));
            log('Seeds', `${data.seeds.length}件のシードノード読み込み`);
            return data.seeds;
        }
    }
    catch (e) {
        log('Seeds', `seeds.json 読み込み失敗: ${e}`);
    }
    return [];
}
function getMyHost() {
    return process.env.SEED_HOST || 'mail.shudo-physics.com';
}
function connectToSeeds() {
    const seeds = loadSeeds();
    const myHost = getMyHost();
    for (const seed of seeds) {
        if (seed.host === myHost) {
            myPriority = seed.priority;
            log('Seeds', `自分を検出: priority ${myPriority}`);
            continue;
        }
        connectToSeed(seed);
    }
    determinePrimary();
}
function connectToSeed(seed) {
    if (seedPeers.has(seed.host))
        return;
    log('Seeds', `シードノードに接続中: ${seed.host}:${CONFIG.SEED_PORT}`);
    const socket = net.connect(CONFIG.SEED_PORT, seed.host, () => {
        log('Seeds', `シードノード接続成功: ${seed.host}`);
        const buffer = new PacketBuffer();
        const conn = {
            socket, buffer,
            host: seed.host,
            priority: seed.priority,
            publicKey: seed.publicKey,
            lastPing: Date.now(),
        };
        seedPeers.set(seed.host, conn);
        sendTCP(socket, { type: 'seed_hello', data: { host: getMyHost(), priority: myPriority } });
        sendTCP(socket, { type: 'sync_trusted_keys', data: trustManager.getTrustedKeysFile() });
        socket.on('data', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets)
                handleSeedPacket(seed.host, packet);
        });
        socket.on('close', () => {
            seedPeers.delete(seed.host);
            log('Seeds', `シードノード切断: ${seed.host}`);
            setTimeout(() => connectToSeed(seed), 3000);
            determinePrimary();
        });
        socket.on('error', (err) => {
            log('Seeds', `シードノードエラー (${seed.host}): ${err.message}`);
        });
    });
    socket.on('error', (err) => {
        log('Seeds', `シードノード接続失敗 (${seed.host}): ${err.message}`);
        setTimeout(() => connectToSeed(seed), 5000);
    });
}
function determinePrimary() {
    let lowestPriority = myPriority;
    for (const [, conn] of seedPeers) {
        if (conn.priority < lowestPriority)
            lowestPriority = conn.priority;
    }
    const wasPrimary = isPrimary;
    isPrimary = (myPriority === lowestPriority);
    if (isPrimary !== wasPrimary) {
        log('Seeds', isPrimary ? '★ プライマリに昇格' : '→ セカンダリに降格');
    }
}
function findPrimaryHost() {
    let primaryHost = getMyHost();
    let lowestPriority = myPriority;
    for (const [host, conn] of seedPeers) {
        if (conn.priority < lowestPriority) {
            lowestPriority = conn.priority;
            primaryHost = host;
        }
    }
    return primaryHost;
}
function broadcastToSeeds(packet) {
    for (const [, conn] of seedPeers)
        sendTCP(conn.socket, packet);
}
// ============================================================
// シードノード間TCPサーバー（ポート40000）
// ============================================================
function startSeedServer() {
    const server = net.createServer((socket) => {
        const buffer = new PacketBuffer();
        let peerHost = socket.remoteAddress || 'unknown';
        log('Seeds', `シードノードからの接続受付: ${peerHost}`);
        socket.on('data', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets) {
                if (packet.type === 'seed_hello' && packet.data?.host) {
                    peerHost = packet.data.host;
                    if (!seedPeers.has(peerHost)) {
                        seedPeers.set(peerHost, {
                            socket, buffer,
                            host: peerHost,
                            priority: packet.data.priority || 999,
                            publicKey: '',
                            lastPing: Date.now(),
                        });
                        log('Seeds', `シードノード登録: ${peerHost} (priority: ${packet.data.priority})`);
                        determinePrimary();
                    }
                }
                handleSeedPacket(peerHost, packet);
            }
        });
        socket.on('close', () => {
            seedPeers.delete(peerHost);
            log('Seeds', `シードノード切断（受付側）: ${peerHost}`);
            determinePrimary();
        });
        socket.on('error', (err) => {
            log('Seeds', `シードノードエラー（受付側）: ${err.message}`);
        });
    });
    server.listen(CONFIG.SEED_PORT, () => {
        log('Seeds', `シードノード間TCPサーバー起動: port ${CONFIG.SEED_PORT}`);
    });
}
// ============================================================
// シードノード間パケットハンドリング
// ============================================================
function handleSeedPacket(peerHost, packet) {
    const conn = seedPeers.get(peerHost);
    switch (packet.type) {
        case 'seed_hello': break;
        case 'ping':
            if (conn) {
                conn.lastPing = Date.now();
                sendTCP(conn.socket, { type: 'pong' });
            }
            break;
        case 'pong':
            if (conn)
                conn.lastPing = Date.now();
            break;
        case 'sync_trusted_keys':
            if (packet.data) {
                trustManager.syncTrustedKeys(packet.data);
                log('Seeds', `trusted_keys 同期受信: ${peerHost}`);
            }
            break;
        case 'who_is_primary':
            if (conn)
                sendTCP(conn.socket, { type: 'primary_is', data: { host: findPrimaryHost() } });
            break;
        case 'random_result':
            broadcastToNodes(packet);
            broadcastToClients(packet);
            break;
        case 'update':
            if (packet.data) {
                trustManager.verifyUpdate(packet.data).then(valid => {
                    if (valid) {
                        latestNodeCode = packet.data;
                        fs.writeFileSync('./latest_update.json', JSON.stringify(packet.data));
                        broadcastToNodes(packet);
                        log('Seeds', `アップデート同期: v${packet.data.version} from ${peerHost}`);
                    }
                });
            }
            break;
        case 'block_broadcast':
            broadcastToNodes(packet);
            broadcastToClients({ type: 'new_block', data: packet.data });
            break;
        default:
            log('Seeds', `不明なシード間パケット: ${packet.type} from ${peerHost}`);
    }
}
function startSeedHeartbeat() {
    setInterval(() => {
        const now = Date.now();
        for (const [host, conn] of seedPeers) {
            if (now - conn.lastPing > CONFIG.HEARTBEAT_TIMEOUT) {
                log('Seeds', `シードノードタイムアウト: ${host}`);
                conn.socket.destroy();
                seedPeers.delete(host);
                determinePrimary();
                continue;
            }
            sendTCP(conn.socket, { type: 'ping', timestamp: now });
        }
    }, CONFIG.HEARTBEAT_INTERVAL);
}
// ============================================================
// TCPサーバー（フルノード用 :5000）
// ============================================================
function startTCPServer() {
    const server = net.createServer((socket) => {
        const nodeId = generateId('node');
        const buffer = new PacketBuffer();
        const conn = {
            socket, buffer,
            info: { id: nodeId, host: socket.remoteAddress, connectedAt: Date.now(), lastPing: Date.now(), chainHeight: 0, difficulty: 1 }
        };
        fullNodes.set(nodeId, conn);
        log('TCP', `フルノード接続: ${nodeId} (${socket.remoteAddress})`);
        broadcastToNodes({ type: 'new_node', data: { id: nodeId, host: socket.remoteAddress } }, nodeId);
        socket.on('data', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets)
                handleNodePacket(nodeId, packet);
        });
        socket.on('close', () => {
            fullNodes.delete(nodeId);
            log('TCP', `フルノード切断: ${nodeId}`);
            broadcastToNodes({ type: 'node_left', data: { id: nodeId } });
        });
        socket.on('error', (err) => log('TCP', `エラー (${nodeId}): ${err.message}`));
    });
    server.listen(CONFIG.TCP_PORT, () => {
        log('TCP', `フルノード用TCPサーバー起動: port ${CONFIG.TCP_PORT}`);
    });
}
// ============================================================
// WSSサーバー（クライアント用 :443 / :8443）
// ============================================================
function startWSSServer() {
    let server;
    if (fs.existsSync(CONFIG.SSL_CERT) && fs.existsSync(CONFIG.SSL_KEY)) {
        server = createHTTPSServer({
            cert: fs.readFileSync(CONFIG.SSL_CERT),
            key: fs.readFileSync(CONFIG.SSL_KEY),
        });
        server.listen(CONFIG.WSS_PORT, () => {
            log('WSS', `クライアント用WSSサーバー起動: port ${CONFIG.WSS_PORT} (HTTPS)`);
        });
    }
    else {
        server = createHTTPServer();
        server.listen(CONFIG.WSS_DEV_PORT, () => {
            log('WSS', `クライアント用WSサーバー起動: port ${CONFIG.WSS_DEV_PORT} (HTTP, 開発モード)`);
        });
    }
    const wss = new WebSocketServer({ server });
    wss.on('connection', (ws) => {
        const clientId = generateId('client');
        const buffer = new PacketBuffer();
        const conn = { ws, buffer, id: clientId, connectedAt: Date.now() };
        clients.set(clientId, conn);
        log('WSS', `クライアント接続: ${clientId}`);
        ws.on('message', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets)
                handleClientPacket(clientId, packet);
        });
        ws.on('close', () => { clients.delete(clientId); log('WSS', `クライアント切断: ${clientId}`); });
        ws.on('error', (err) => log('WSS', `エラー (${clientId}): ${err.message}`));
    });
}
// ============================================================
// パケットハンドリング（フルノード）
// ============================================================
function handleNodePacket(nodeId, packet) {
    const conn = fullNodes.get(nodeId);
    if (!conn)
        return;
    switch (packet.type) {
        case 'pong':
            conn.info.lastPing = Date.now();
            break;
        case 'register':
            conn.info.chainHeight = packet.data?.chainHeight || 0;
            conn.info.difficulty = packet.data?.difficulty || 1;
            sendTCP(conn.socket, {
                type: 'node_list',
                data: { nodes: Array.from(fullNodes.values()).map(n => ({ id: n.info.id, host: n.info.host, chainHeight: n.info.chainHeight })) }
            });
            log('TCP', `ノード登録: ${nodeId} (height: ${conn.info.chainHeight})`);
            // --- チェーン同期: 既存ノードからチェーンを取得させる ---
            {
                const otherNodes = Array.from(fullNodes.entries()).filter(([id]) => id !== nodeId);
                if (otherNodes.length > 0) {
                    const best = otherNodes.reduce((a, b) => a[1].info.chainHeight >= b[1].info.chainHeight ? a : b);
                    if (best[1].info.chainHeight > conn.info.chainHeight) {
                        // 最長チェーンを持つノードに、新ノード向けにチェーンを送るよう依頼
                        sendTCP(best[1].socket, {
                            type: 'send_chain_to',
                            data: { targetNodeId: nodeId, fromHeight: conn.info.chainHeight }
                        });
                        log('TCP', `チェーン同期依頼: ${best[0]} → ${nodeId} (from height ${conn.info.chainHeight})`);
                    }
                }
            }
            break;
        case 'height':
            conn.info.chainHeight = packet.data?.height || 0;
            if (packet.data?.difficulty)
                conn.info.difficulty = packet.data.difficulty;
            if (packet.data?.clientId) {
                const client = clients.get(packet.data.clientId);
                if (client)
                    sendWS(client.ws, packet);
            }
            break;
        case 'block_broadcast':
            broadcastToNodes(packet, nodeId);
            broadcastToSeeds(packet);
            break;
        case 'tx_broadcast':
            broadcastToNodes(packet, nodeId);
            // マイニング中のクライアントに新Tx通知 → テンプレート再取得のトリガー
            broadcastToClients({ type: 'new_tx', data: { count: 1 } });
            break;
        case 'block_accepted': {
            broadcastToClients({ type: 'new_block', data: packet.data });
            if (packet.data?.minerId) {
                const client = clients.get(packet.data.minerId);
                if (client)
                    sendWS(client.ws, { type: 'block_accepted', data: packet.data });
            }
            break;
        }
        case 'block_rejected': {
            if (packet.data?.minerId) {
                const client = clients.get(packet.data.minerId);
                if (client)
                    sendWS(client.ws, { type: 'block_rejected', data: packet.data });
            }
            break;
        }
        case 'balance':
        case 'chain':
        case 'chain_chunk':
        case 'chain_sync_done':
        case 'token_info':
        case 'tokens_list':
        case 'rate':
        case 'tx_result':
        case 'block_template':
        case 'admin_mempool':
        case 'admin_transactions':
        case 'admin_account':
        case 'admin_blocks':
        case 'admin_mint_result':
        case 'admin_distribute_result':
        case 'admin_clear_mempool_result':
        case 'admin_remove_tx_result':
            if (packet.data?.clientId) {
                const client = clients.get(packet.data.clientId);
                if (client)
                    sendWS(client.ws, packet);
            }
            break;
        case 'random_commit':
            handleRandomCommit(nodeId, packet);
            break;
        case 'random_reveal':
            handleRandomReveal(nodeId, packet);
            break;
        case 'chain_sync': {
            // 既存ノードが新ノード向けにチェーンデータを送ってきた → 対象ノードに転送
            const targetId = packet.data?.targetNodeId;
            if (targetId) {
                const target = fullNodes.get(targetId);
                if (target) {
                    sendTCP(target.socket, {
                        type: 'chain_sync',
                        data: {
                            blocks: packet.data.blocks,
                            chunkIndex: packet.data.chunkIndex,
                            totalChunks: packet.data.totalChunks,
                            totalHeight: packet.data.totalHeight,
                        }
                    });
                    log('TCP', `チェーン同期中継: → ${targetId} (チャンク ${packet.data.chunkIndex}/${packet.data.totalChunks})`);
                }
            }
            break;
        }
        case 'request_chain': {
            // フォールバック: ノードが直接チェーンを要求してきた
            const fromHeight = packet.data?.fromHeight || 0;
            const otherNodes = Array.from(fullNodes.entries()).filter(([id]) => id !== nodeId);
            if (otherNodes.length > 0) {
                const best = otherNodes.reduce((a, b) => a[1].info.chainHeight >= b[1].info.chainHeight ? a : b);
                if (best[1].info.chainHeight > fromHeight) {
                    sendTCP(best[1].socket, {
                        type: 'send_chain_direct',
                        data: { targetNodeId: nodeId, fromHeight }
                    });
                    log('TCP', `フォールバック同期依頼: ${best[0]} → ${nodeId}`);
                }
                else {
                    // 他に長いチェーンを持つノードがない
                    sendTCP(conn.socket, { type: 'chain_sync_response', data: { blocks: [] } });
                }
            }
            else {
                sendTCP(conn.socket, { type: 'chain_sync_response', data: { blocks: [] } });
            }
            break;
        }
        case 'chain_sync_direct': {
            // フォールバック: 既存ノードが直接チェーンを返してきた → 要求元に転送
            const targetId = packet.data?.targetNodeId;
            if (targetId) {
                const target = fullNodes.get(targetId);
                if (target) {
                    sendTCP(target.socket, { type: 'chain_sync_response', data: { blocks: packet.data.blocks } });
                    log('TCP', `フォールバック同期中継: → ${targetId} (${packet.data.blocks?.length || 0}ブロック)`);
                }
            }
            break;
        }
        case 'get_latest_files':
            sendTCP(conn.socket, { type: 'latest_files', data: { nodeCode: latestNodeCode, trustedKeys: trustManager.getTrustedKeysFile() } });
            log('TCP', `最新ファイル配布: ${nodeId}`);
            break;
        case 'check_sync': {
            // ノードが自分の高さを申告 → 最長ノードより遅れてたら同期を指示
            const myHeight = packet.data?.height || 0;
            const otherNodes = Array.from(fullNodes.entries()).filter(([id]) => id !== nodeId);
            if (otherNodes.length > 0) {
                const best = otherNodes.reduce((a, b) => a[1].info.chainHeight >= b[1].info.chainHeight ? a : b);
                if (best[1].info.chainHeight > myHeight + 1) {
                    sendTCP(best[1].socket, {
                        type: 'send_chain_to',
                        data: { targetNodeId: nodeId, fromHeight: myHeight }
                    });
                    sendTCP(conn.socket, { type: 'sync_needed', data: { bestHeight: best[1].info.chainHeight } });
                    log('TCP', `定期同期: ${nodeId} (height ${myHeight}) ← ${best[0]} (height ${best[1].info.chainHeight})`);
                }
            }
            break;
        }
        case 'who_is_primary':
            sendTCP(conn.socket, { type: 'primary_is', data: { host: findPrimaryHost() } });
            break;
        default: log('TCP', `不明なパケット: ${packet.type} from ${nodeId}`);
    }
}
// ============================================================
// パケットハンドリング（クライアント）
// ============================================================
function handleClientPacket(clientId, packet) {
    const conn = clients.get(clientId);
    if (!conn)
        return;
    switch (packet.type) {
        case 'mine':
            broadcastToNodes({ type: 'block_broadcast', data: { ...packet.data, minerId: clientId } });
            break;
        case 'tx':
            relayToNode({ type: 'tx', data: { ...packet.data, clientId } });
            break;
        case 'get_balance':
        case 'get_chain':
        case 'get_height':
        case 'get_token':
        case 'get_rate':
        case 'get_block_template':
        case 'get_tokens_list':
            relayToNode({ type: packet.type, data: { ...packet.data, clientId } });
            break;
        case 'update':
            handleUpdateFromClient(clientId, packet);
            break;
        case 'add_member':
            handleAddMember(clientId, packet);
            break;
        case 'admin_auth':
            handleAdminAuth(clientId, packet);
            break;
        case 'admin_status':
            handleAdminStatus(clientId);
            break;
        case 'admin_nodes':
            handleAdminNodes(clientId);
            break;
        case 'admin_get_keys':
            handleAdminGetKeys(clientId);
            break;
        case 'admin_get_account':
            handleAdminGetAccount(clientId, packet);
            break;
        case 'admin_get_blocks':
            handleAdminGetBlocks(clientId, packet);
            break;
        case 'admin_mempool':
            handleAdminMempool(clientId);
            break;
        case 'admin_get_transactions':
            handleAdminGetTransactions(clientId, packet);
            break;
        case 'admin_remove_key':
            handleAdminRemoveKey(clientId, packet);
            break;
        case 'admin_mint':
            handleAdminMint(clientId, packet);
            break;
        case 'admin_distribute':
            handleAdminDistribute(clientId, packet);
            break;
        case 'admin_clear_mempool':
            handleAdminClearMempool(clientId);
            break;
        case 'admin_remove_tx':
            handleAdminRemoveTx(clientId, packet);
            break;
        default: log('WSS', `不明なパケット: ${packet.type} from ${clientId}`);
    }
}
// ============================================================
// 中継
// ============================================================
function broadcastToNodes(packet, excludeId) {
    for (const [id, conn] of fullNodes) {
        if (id !== excludeId)
            sendTCP(conn.socket, packet);
    }
}
function broadcastToClients(packet) {
    for (const [, conn] of clients)
        sendWS(conn.ws, packet);
}
function relayToNode(packet) {
    const nodes = Array.from(fullNodes.values());
    if (nodes.length === 0) {
        if (packet.data?.clientId) {
            const client = clients.get(packet.data.clientId);
            if (client)
                sendWS(client.ws, { type: 'error', data: { message: 'フルノードが利用できません' } });
        }
        return;
    }
    const best = nodes.reduce((a, b) => a.info.chainHeight >= b.info.chainHeight ? a : b);
    sendTCP(best.socket, packet);
}
// ============================================================
// アップデート & メンバー管理
// ============================================================
async function handleUpdateFromClient(clientId, packet) {
    const update = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    if (!await trustManager.verifyUpdate(update)) {
        sendWS(client.ws, { type: 'update_result', data: { success: false, message: '検証失敗' } });
        return;
    }
    latestNodeCode = update;
    fs.writeFileSync('./latest_update.json', JSON.stringify(update));
    log('Update', `アップデート受信: v${update.version} by ${update.signer.slice(0, 16)}...`);
    broadcastToNodes({ type: 'update', data: update });
    broadcastToSeeds({ type: 'update', data: update });
    sendWS(client.ws, { type: 'update_result', data: { success: true, message: `v${update.version} を配布しました` } });
}
async function handleAddMember(clientId, packet) {
    const { publicKey, role, addedBy, signature } = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    const success = await trustManager.addMember(publicKey, role, addedBy, signature);
    sendWS(client.ws, { type: 'add_member_result', data: { success } });
    if (success) {
        const keysData = trustManager.getTrustedKeysFile();
        broadcastToNodes({ type: 'sync_trusted_keys', data: keysData });
        broadcastToSeeds({ type: 'sync_trusted_keys', data: keysData });
    }
}
// ============================================================
// 管理者パネル用ハンドラ
// ============================================================
async function handleAdminAuth(clientId, packet) {
    const { publicKey, challenge, signature } = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    try {
        if (!trustManager.isTrusted(publicKey)) {
            sendWS(client.ws, {
                type: 'admin_auth_result',
                data: { success: false, message: '信頼されていない公開鍵です' }
            });
            return;
        }
        const messageBytes = new TextEncoder().encode(challenge);
        const signatureBytes = hexToBytes(signature);
        const publicKeyBytes = hexToBytes(publicKey);
        const isValid = await Ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
        if (!isValid) {
            sendWS(client.ws, {
                type: 'admin_auth_result',
                data: { success: false, message: '署名検証失敗' }
            });
            return;
        }
        const role = trustManager.getRole(publicKey);
        client.authenticatedKey = publicKey;
        client.adminRole = role;
        sendWS(client.ws, {
            type: 'admin_auth_result',
            data: { success: true, role }
        });
        log('Admin', `管理者認証成功: ${publicKey.slice(0, 16)}... (${role})`);
    }
    catch (e) {
        log('Admin', `認証エラー: ${e instanceof Error ? e.message : String(e)}`);
        console.error('Admin auth error details:', e);
        sendWS(client.ws, {
            type: 'admin_auth_result',
            data: { success: false, message: '認証エラー' }
        });
    }
}
function isAdminAuthenticated(clientId) {
    const client = clients.get(clientId);
    if (!client)
        return false;
    return !!client.authenticatedKey;
}
function getAdminRole(clientId) {
    const client = clients.get(clientId);
    return client ? client.adminRole || null : null;
}
function handleAdminStatus(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const nodes = Array.from(fullNodes.values());
    const bestNode = nodes.length > 0
        ? nodes.reduce((a, b) => a.info.chainHeight >= b.info.chainHeight ? a : b)
        : null;
    const status = {
        nodeCount: fullNodes.size,
        clientCount: clients.size,
        chainHeight: bestNode?.info.chainHeight || 0,
        difficulty: bestNode?.info.difficulty || 1,
        latestBlock: null
    };
    sendWS(client.ws, { type: 'admin_status', data: status });
}
function handleAdminNodes(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const nodeList = Array.from(fullNodes.values()).map(conn => conn.info);
    sendWS(client.ws, {
        type: 'admin_nodes',
        data: { nodes: nodeList }
    });
}
function handleAdminGetKeys(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認��が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const keysData = trustManager.getTrustedKeysFile();
    sendWS(client.ws, {
        type: 'admin_trusted_keys',
        data: keysData
    });
}
function handleAdminGetAccount(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const address = packet.data.address;
    relayToNode({
        type: 'get_balance',
        data: {
            address,
            clientId,
            adminRequest: true
        }
    });
}
function handleAdminGetBlocks(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const limit = packet.data.limit || 10;
    relayToNode({
        type: 'get_chain',
        data: {
            from: -limit,
            clientId,
            admin: true
        }
    });
}
function handleAdminMempool(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    relayToNode({
        type: 'get_mempool',
        data: { clientId }
    });
}
function handleAdminGetTransactions(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const limit = packet.data.limit || 50;
    relayToNode({
        type: 'get_recent_transactions',
        data: {
            limit,
            clientId
        }
    });
}
async function handleAdminRemoveKey(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_remove_key_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { publicKey, removedBy } = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    const success = trustManager.removeMember(publicKey, removedBy);
    sendWS(client.ws, {
        type: 'admin_remove_key_result',
        data: { success }
    });
    if (success) {
        const keysData = trustManager.getTrustedKeysFile();
        broadcastToNodes({ type: 'sync_trusted_keys', data: keysData });
        broadcastToSeeds({ type: 'sync_trusted_keys', data: keysData });
    }
}
async function handleAdminMint(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_mint_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { address, amount } = packet.data;
    log('Admin', `コイン発行: ${address} に ${amount} BTR`);
    relayToNode({
        type: 'admin_mint',
        data: { address, amount, clientId }
    });
}
async function handleAdminDistribute(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_distribute_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { distributions } = packet.data;
    log('Admin', `一括配給: ${distributions.length} 件`);
    relayToNode({
        type: 'admin_distribute',
        data: { distributions, clientId }
    });
}
async function handleAdminClearMempool(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_clear_mempool_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    log('Admin', 'Mempool全消去リクエスト');
    relayToNode({
        type: 'admin_clear_mempool',
        data: { clientId }
    });
}
async function handleAdminRemoveTx(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_remove_tx_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { signature } = packet.data;
    log('Admin', `トランザクション削除: ${signature.slice(0, 16)}...`);
    relayToNode({
        type: 'admin_remove_tx',
        data: { signature, clientId }
    });
}
// ============================================================
// 分散乱数
// ============================================================
function startRandomRound() {
    if (!isPrimary)
        return;
    const activeNodes = Array.from(fullNodes.values()).map(n => n.info);
    const result = randomManager.startRound(activeNodes);
    if (result.fallback) {
        broadcastRandomResult();
        return;
    }
    for (const nodeId of result.selectedNodes) {
        const conn = fullNodes.get(nodeId);
        if (conn)
            sendTCP(conn.socket, { type: 'random_request' });
    }
    setTimeout(() => {
        randomManager.handleTimeout();
        if (randomManager.getPhase() === 'idle')
            broadcastRandomResult();
    }, CONFIG.RANDOM_TIMEOUT);
}
function handleRandomCommit(nodeId, packet) {
    const allCommitted = randomManager.receiveCommit(nodeId, packet.data.hash);
    if (allCommitted) {
        for (const [id, conn] of fullNodes) {
            if (randomManager['selectedNodes'].includes(id))
                sendTCP(conn.socket, { type: 'random_reveal_request' });
        }
    }
}
function handleRandomReveal(nodeId, packet) {
    if (randomManager.receiveReveal(nodeId, packet.data.value))
        broadcastRandomResult();
}
function broadcastRandomResult() {
    const random = randomManager.getCurrentRandom();
    const packet = { type: 'random_result', data: { random } };
    broadcastToNodes(packet);
    broadcastToClients(packet);
    broadcastToSeeds(packet);
    log('Random', `共通乱数配布: ${random.slice(0, 16)}...`);
}
// ============================================================
// ハートビート
// ============================================================
function startHeartbeat() {
    setInterval(() => {
        const now = Date.now();
        for (const [nodeId, conn] of fullNodes) {
            if (now - conn.info.lastPing > CONFIG.HEARTBEAT_TIMEOUT) {
                log('Heartbeat', `タイムアウト: ${nodeId}`);
                conn.socket.destroy();
                fullNodes.delete(nodeId);
                broadcastToNodes({ type: 'node_left', data: { id: nodeId } });
                continue;
            }
            sendTCP(conn.socket, { type: 'ping', timestamp: now });
        }
    }, CONFIG.HEARTBEAT_INTERVAL);
}
// ============================================================
// 定期タスク
// ============================================================
function startPeriodicTasks() {
    setInterval(startRandomRound, CONFIG.RANDOM_INTERVAL);
    setTimeout(startRandomRound, 5000);
    setInterval(() => {
        const p = isPrimary ? '★PRIMARY' : 'SECONDARY';
        log('Stats', `[${p}] ノード: ${fullNodes.size}, クライアント: ${clients.size}, シード: ${seedPeers.size}`);
    }, 30000);
}
// ============================================================
// エントリーポイント ★変更箇所
// ============================================================
function main() {
    console.log('========================================');
    console.log('  BTR (Buturi Coin) Seed Node');
    console.log('========================================');
    trustManager = new TrustManager(CONFIG.ROOT_PUBLIC_KEY);
    randomManager = new RandomManager();
    // --- ★ 初回配布対応: latest_update.json が無ければ node.js から自動生成 ---
    const latestCodePath = path.resolve('./latest_update.json');
    if (fs.existsSync(latestCodePath)) {
        try {
            latestNodeCode = JSON.parse(fs.readFileSync(latestCodePath, 'utf-8'));
            log('Init', `最新コード読み込み: v${latestNodeCode?.version}`);
        }
        catch (e) {
            log('Init', '最新コード読み込み失敗');
        }
    }
    else {
        const nodeJsPath = path.resolve('./node.js');
        if (fs.existsSync(nodeJsPath)) {
            try {
                const code = fs.readFileSync(nodeJsPath, 'utf-8');
                const hash = createHash('sha256').update(code).digest('hex');
                latestNodeCode = {
                    version: '0.0.1',
                    code,
                    hash,
                    signer: '',
                    signature: '',
                };
                fs.writeFileSync(latestCodePath, JSON.stringify(latestNodeCode, null, 2));
                log('Init', `node.js から初回配布パッケージ自動生成: v0.0.1`);
            }
            catch (e) {
                log('Init', `node.js 読み込み失敗: ${e}`);
            }
        }
        else {
            log('Init', '⚠ latest_update.json も node.js も見つかりません');
        }
    }
    // --- ★ ここまで ---
    startTCPServer();
    startWSSServer();
    startSeedServer();
    startHeartbeat();
    startSeedHeartbeat();
    startPeriodicTasks();
    connectToSeeds();
    log('Init', 'シードノード起動完了');
    log('Init', `ホスト: ${getMyHost()}`);
    log('Init', `ポート: TCP=${CONFIG.TCP_PORT}, WSS=${CONFIG.WSS_PORT}/${CONFIG.WSS_DEV_PORT}, Seed=${CONFIG.SEED_PORT}`);
}
main();
//# sourceMappingURL=index.js.map