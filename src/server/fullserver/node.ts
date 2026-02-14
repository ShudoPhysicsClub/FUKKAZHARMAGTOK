// ============================================================
// BTR (Buturi Coin) - フルノード
// ランチャーからforkされて動く
// ============================================================

import { connect, Socket } from 'net';
import { createHash, randomBytes } from 'crypto';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import * as fs from 'fs'; // ★ mkdirSync用に追加
type ExtPoint = [bigint, bigint, bigint, bigint];
type AffinePoint = [bigint, bigint];

class Ed25519 {
  // ── 定数 ──
  private static readonly p = 2n ** 255n - 19n;
  private static readonly L =
    2n ** 252n + 27742317777372353535851937790883648493n;
  private static readonly d =
    37095705934669439343138083508754565189542113879843219016388785533085940283555n;
  private static readonly SQRT_M1 =
    19681161376707505956807079304988542015446066515923890162744021073123829784752n;

  private static readonly Gx =
    15112221349535400772501151409588531511454012693041857206046113283949847762202n;
  private static readonly Gy =
    46316835694926478169428394003475163141307993866256225615783033603165251855960n;
  private static readonly G_EXT: ExtPoint = [
    Ed25519.Gx,
    Ed25519.Gy,
    1n,
    (Ed25519.Gx * Ed25519.Gy) % Ed25519.p,
  ];

  private static readonly ED25519_OID = new Uint8Array([
    0x06, 0x03, 0x2b, 0x65, 0x70,
  ]);

  // ── Fixed-window テーブル (遅延初期化, w=4) ──
  private static readonly W = 4;
  private static _gTable: ExtPoint[] | null = null;
  private static get gTable(): ExtPoint[] {
    if (!this._gTable) {
      const size = 1 << this.W;
      const t: ExtPoint[] = new Array(size);
      t[0] = [0n, 1n, 1n, 0n];
      t[1] = this.G_EXT;
      for (let i = 2; i < size; i++) t[i] = this.extAdd(t[i - 1], this.G_EXT);
      this._gTable = t;
    }
    return this._gTable;
  }

  // ━━━━━━━━━━━━━ 基本演算 ━━━━━━━━━━━━━

  private static mod(n: bigint, m: bigint): bigint {
    const r = n % m;
    return r < 0n ? r + m : r;
  }

  private static modInv(a: bigint, m: bigint): bigint {
    let r0 = m,
      r1 = a < 0n ? ((a % m) + m) % m : a % m;
    let x0 = 0n,
      x1 = 1n;
    while (r1 !== 0n) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [x0, x1] = [x1, x0 - q * x1];
    }
    return x0 < 0n ? x0 + m : x0;
  }

  private static modPow(base: bigint, exp: bigint, m: bigint): bigint {
    let result = 1n;
    base = ((base % m) + m) % m;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % m;
      base = (base * base) % m;
      exp >>= 1n;
    }
    return result;
  }

  // ━━━━━━━━━━━━━ 楕円曲線演算 (Extended 座標) ━━━━━━━━━━━━━

  private static extAdd(p1: ExtPoint, p2: ExtPoint): ExtPoint {
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

  private static extDouble(pt: ExtPoint): ExtPoint {
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

  private static extToAffine(pt: ExtPoint): AffinePoint {
    const [X, Y, Z] = pt;
    if (Z === 0n) return [0n, 1n];
    const zi = this.modInv(Z, this.p);
    return [this.mod(X * zi, this.p), this.mod(Y * zi, this.p)];
  }

  // ━━━━━━━━━━━━━ スカラー乗算 ━━━━━━━━━━━━━

  private static scalarMultG(k: bigint): ExtPoint {
    const table = this.gTable;
    const mask = BigInt((1 << this.W) - 1);
    const steps = 64;
    let R: ExtPoint = [0n, 1n, 1n, 0n];
    for (let i = steps - 1; i >= 0; i--) {
      for (let j = 0; j < this.W; j++) R = this.extDouble(R);
      const idx = Number((k >> BigInt(i * this.W)) & mask);
      if (idx !== 0) R = this.extAdd(R, table[idx]);
    }
    return R;
  }

  private static scalarMult(k: bigint, point: ExtPoint): ExtPoint {
    let R: ExtPoint = [0n, 1n, 1n, 0n];
    let Q = point;
    while (k > 0n) {
      if (k & 1n) R = this.extAdd(R, Q);
      Q = this.extDouble(Q);
      k >>= 1n;
    }
    return R;
  }

  private static shamirMult(s: bigint, k: bigint, A: ExtPoint): ExtPoint {
    const GA = this.extAdd(this.G_EXT, A);
    let R: ExtPoint = [0n, 1n, 1n, 0n];
    for (let i = 255; i >= 0; i--) {
      R = this.extDouble(R);
      const sb = (s >> BigInt(i)) & 1n;
      const kb = (k >> BigInt(i)) & 1n;
      if (sb && kb) R = this.extAdd(R, GA);
      else if (sb) R = this.extAdd(R, this.G_EXT);
      else if (kb) R = this.extAdd(R, A);
    }
    return R;
  }

  // ━━━━━━━━━━━━━ エンコーディング ━━━━━━━━━━━━━

  private static pointToBytes(point: AffinePoint): Uint8Array {
    const [x, y] = point;
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = Number((y >> BigInt(i * 8)) & 0xffn);
    if (x & 1n) out[31] |= 0x80;
    return out;
  }

  private static bytesToPoint(bytes: Uint8Array): ExtPoint {
    if (bytes.length !== 32) throw new Error("Invalid point encoding");
    let y = 0n;
    for (let i = 0; i < 32; i++)
      y |= BigInt(bytes[i] & (i === 31 ? 0x7f : 0xff)) << BigInt(i * 8);
    if (y >= this.p) throw new Error("y coordinate out of range");

    const x_sign = (bytes[31] & 0x80) !== 0;
    const P = this.p;
    const y2 = (y * y) % P;
    const num = this.mod(y2 - 1n, P);
    const den = this.mod(this.d * y2 + 1n, P);
    const x2 = (num * this.modInv(den, P)) % P;

    if (x2 === 0n) {
      if (x_sign) throw new Error("Invalid point encoding");
      return [0n, y, 1n, 0n];
    }

    let x = this.modPow(x2, (P + 3n) / 8n, P);
    if ((x * x) % P !== this.mod(x2, P)) {
      x = (x * this.SQRT_M1) % P;
      if ((x * x) % P !== this.mod(x2, P))
        throw new Error("Invalid point: no square root");
    }
    if ((x & 1n) !== (x_sign ? 1n : 0n)) x = P - x;

    const xc = (x * x) % P;
    const yc = (y * y) % P;
    if (
      this.mod(yc - xc, P) !==
      this.mod(1n + ((this.d * ((xc * yc) % P)) % P), P)
    )
      throw new Error("Point is not on curve");

    return [x, y, 1n, (x * y) % P];
  }

  private static bigIntToBytes(n: bigint, len: number): Uint8Array {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = Number((n >> BigInt(i * 8)) & 0xffn);
    return out;
  }

  private static bytesToBigInt(bytes: Uint8Array): bigint {
    let r = 0n;
    for (let i = bytes.length - 1; i >= 0; i--)
      r = (r << 8n) | BigInt(bytes[i]);
    return r;
  }

  // ━━━━━━━━━━━━━ ヘルパー ━━━━━━━━━━━━━

  private static async sha512(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(
      await crypto.subtle.digest("SHA-512", data.buffer as ArrayBuffer),
    );
  }

  private static concat(...arrays: Uint8Array[]): Uint8Array {
    let len = 0;
    for (const a of arrays) len += a.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrays) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }

  private static clamp(s: bigint): bigint {
    return (s & ((1n << 255n) - 1n) & ~7n) | (1n << 254n);
  }

  // ━━━━━━━━━━━━━ DERエンコード ━━━━━━━━━━━━━

  private static encodeDerLength(len: number): Uint8Array {
    if (len <= 127) return new Uint8Array([len]);
    let bytesNeeded: number;
    if (len >= 0x1000000) bytesNeeded = 4;
    else if (len >= 0x10000) bytesNeeded = 3;
    else if (len >= 0x100) bytesNeeded = 2;
    else bytesNeeded = 1;
    const res = new Uint8Array(bytesNeeded + 1);
    res[0] = 0x80 | bytesNeeded;
    let t = len;
    for (let i = bytesNeeded; i >= 1; i--) {
      res[i] = t & 0xff;
      t >>= 8;
    }
    return res;
  }

  private static encodeDerSequence(elements: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const el of elements) total += el.length;
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

  private static encodeDerOctetString(bytes: Uint8Array): Uint8Array {
    const len = this.encodeDerLength(bytes.length);
    const res = new Uint8Array(1 + len.length + bytes.length);
    res[0] = 0x04;
    res.set(len, 1);
    res.set(bytes, 1 + len.length);
    return res;
  }

  private static encodeDerBitString(bytes: Uint8Array): Uint8Array {
    const len = this.encodeDerLength(bytes.length + 1);
    const res = new Uint8Array(1 + len.length + 1 + bytes.length);
    res[0] = 0x03;
    res.set(len, 1);
    res[1 + len.length] = 0x00;
    res.set(bytes, 1 + len.length + 1);
    return res;
  }

  // ━━━━━━━━━━━━━ DERデコード ━━━━━━━━━━━━━

  private static parseDerTLV(
    data: Uint8Array,
    offset: number,
  ): { tag: number; value: Uint8Array; end: number } {
    const tag = data[offset++];
    const first = data[offset++];
    let length: number;
    if (first <= 127) {
      length = first;
    } else {
      const n = first & 0x7f;
      length = 0;
      for (let i = 0; i < n; i++) length = (length << 8) | data[offset++];
    }
    return {
      tag,
      value: data.subarray(offset, offset + length),
      end: offset + length,
    };
  }

  private static parseDerChildren(
    data: Uint8Array,
  ): { tag: number; value: Uint8Array }[] {
    const children: { tag: number; value: Uint8Array }[] = [];
    let offset = 0;
    while (offset < data.length) {
      const tlv = this.parseDerTLV(data, offset);
      children.push({ tag: tlv.tag, value: tlv.value });
      offset = tlv.end;
    }
    return children;
  }

  private static unwrapDer(data: Uint8Array, expectedTag: number): Uint8Array {
    const tlv = this.parseDerTLV(data, 0);
    if (tlv.tag !== expectedTag)
      throw new Error(
        `DER: expected 0x${expectedTag.toString(16)}, got 0x${tlv.tag.toString(16)}`,
      );
    return tlv.value;
  }

  private static checkEd25519OID(algSeqValue: Uint8Array): void {
    const children = this.parseDerChildren(algSeqValue);
    if (children.length === 0 || children[0].tag !== 0x06)
      throw new Error("Expected OID");
    const oid = children[0].value;
    if (
      oid.length !== 3 ||
      oid[0] !== 0x2b ||
      oid[1] !== 0x65 ||
      oid[2] !== 0x70
    )
      throw new Error("OID is not Ed25519 (1.3.101.112)");
  }

  // ━━━━━━━━━━━━━ Base64 / PEM ━━━━━━━━━━━━━

  private static base64Encode(data: Uint8Array): string {
    if (typeof Buffer !== "undefined")
      return Buffer.from(data).toString("base64");
    let s = "";
    for (const b of data) s += String.fromCharCode(b);
    return btoa(s);
  }

  private static base64Decode(str: string): Uint8Array {
    if (typeof Buffer !== "undefined")
      return new Uint8Array(Buffer.from(str, "base64"));
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  private static pemDecode(pem: string): Uint8Array {
    return this.base64Decode(pem.replace(/-----.*?-----|\s+/g, ""));
  }

  private static pemEncode(der: Uint8Array, label: string): string {
    const b64 = this.base64Encode(der);
    const lines: string[] = [];
    for (let i = 0; i < b64.length; i += 64)
      lines.push(b64.substring(i, i + 64));
    return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
  }

  // ━━━━━━━━━━━━━ 公開 API (署名) ━━━━━━━━━━━━━

  static async getPublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length !== 32)
      throw new Error("Private key must be 32 bytes");
    const h = await this.sha512(privateKey);
    const s = this.clamp(this.bytesToBigInt(h.subarray(0, 32)));
    return this.pointToBytes(this.extToAffine(this.scalarMultG(s)));
  }

  static async sign(
    message: Uint8Array,
    privateKey: Uint8Array,
  ): Promise<Uint8Array> {
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

  static async verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<boolean> {
    if (signature.length !== 64 || publicKey.length !== 32) return false;
    try {
      const RBytes = signature.subarray(0, 32);
      const S = this.bytesToBigInt(signature.subarray(32, 64));
      if (S >= this.L) return false;
      const R = this.bytesToPoint(RBytes);
      const A = this.bytesToPoint(publicKey);
      const kHash = await this.sha512(this.concat(RBytes, publicKey, message));
      const k = this.mod(this.bytesToBigInt(kHash), this.L);
      const result = this.shamirMult(S, this.mod(this.L - k, this.L), A);
      const [rx, ry] = this.extToAffine(result);
      const [r0x, r0y] = this.extToAffine(R);
      return rx === r0x && ry === r0y;
    } catch {
      return false;
    }
  }

  // ━━━━━━━━━━━━━ 公開 API (PEM) ━━━━━━━━━━━━━

  static privateKeyToPem(raw: Uint8Array): string {
    if (raw.length !== 32)
      throw new Error("Ed25519 private key must be 32 bytes");
    const version = new Uint8Array([0x02, 0x01, 0x00]);
    const algId = this.encodeDerSequence([this.ED25519_OID]);
    const keyOctet = this.encodeDerOctetString(this.encodeDerOctetString(raw));
    return this.pemEncode(
      this.encodeDerSequence([version, algId, keyOctet]),
      "PRIVATE KEY",
    );
  }

  static pemToPrivateKey(pem: string): Uint8Array {
    const outer = this.unwrapDer(this.pemDecode(pem), 0x30);
    const children = this.parseDerChildren(outer);
    if (children.length < 3) throw new Error("Invalid PKCS#8");
    this.checkEd25519OID(children[1].value);
    if (children[2].tag !== 0x04) throw new Error("Expected OCTET STRING");
    const inner = this.unwrapDer(children[2].value, 0x04);
    if (inner.length !== 32)
      throw new Error(`Expected 32 bytes, got ${inner.length}`);
    return new Uint8Array(inner);
  }

  static publicKeyToPem(raw: Uint8Array): string {
    if (raw.length !== 32)
      throw new Error("Ed25519 public key must be 32 bytes");
    const algId = this.encodeDerSequence([this.ED25519_OID]);
    const bitStr = this.encodeDerBitString(raw);
    return this.pemEncode(
      this.encodeDerSequence([algId, bitStr]),
      "PUBLIC KEY",
    );
  }

  static pemToPublicKey(pem: string): Uint8Array {
    const outer = this.unwrapDer(this.pemDecode(pem), 0x30);
    const children = this.parseDerChildren(outer);
    if (children.length < 2) throw new Error("Invalid SPKI");
    this.checkEd25519OID(children[0].value);
    if (children[1].tag !== 0x03) throw new Error("Expected BIT STRING");
    const bits = children[1].value;
    if (bits[0] !== 0x00) throw new Error("BIT STRING unused bits must be 0");
    const pub = bits.subarray(1);
    if (pub.length !== 32)
      throw new Error(`Expected 32 bytes, got ${pub.length}`);
    return new Uint8Array(pub);
  }
}

const DELIMITER: string = '\nLINE_BREAK\n';
const BTR_ADDRESS: string = '0x0000000000000000';

// ============================================================
// 設定
// ============================================================

const CONFIG = {
  SEED_HOST: 'mail.shudo-physics.com',
  SEED_PORT: 5000,
  CHAIN_FILE: './chain.json',
  ACCOUNTS_FILE: './accounts.json',
  TOKENS_FILE: './tokens.json',

  // ジェネシス設定
  TOTAL_SUPPLY: 5_000_000_000,
  BLOCK_TIME: 1,
  BLOCK_REWARD_MIN: 80,
  BLOCK_REWARD_MAX: 120,
  GAS_FEE: 1,
  TOKEN_CREATION_FEE: 10_000,
  TOKEN_RENAME_FEE: 500,
  TIMESTAMP_TOLERANCE: 10 * 60 * 1000,  // ±10分
  MAX_BLOCK_SIZE: 3 * 1024 * 1024,       // 3MB
  DIFFICULTY_WINDOW: 10,                   // 直近10ブロック
  ROOT_PUBLIC_KEY: '04920517f44339fed12ebbc8f2c0ae93a0c2bfa4a9ef4bfee1c6f12b452eab70',
};

// ============================================================
// 型定義
// ============================================================

interface Transaction {
  type: 'transfer' | 'create_token' | 'token_transfer' | 'swap' | 'rename_token';
  token: string;
  from: string;
  publicKey: string;
  to?: string;
  amount?: number;
  fee: number;
  nonce: number;
  timestamp: number;
  signature: string;
  data?: TransactionData;
}

interface TransactionData {
  name?: string;
  symbol?: string;
  totalSupply?: number;
  poolRatio?: number;
  distribution?: 'creator' | 'mining' | 'split' | 'airdrop';
  tokenIn?: string;
  tokenOut?: string;
  amountIn?: number;
  minAmountOut?: number;
  newName?: string;
}

interface Block {
  height: number;
  previousHash: string;
  timestamp: number;
  nonce: number;
  difficulty: number;
  miner: string;
  reward: number;
  transactions: Transaction[];
  hash: string;
}

interface GenesisBlock extends Block {
  config: typeof CONFIG;
  message: string;
}

interface Account {
  address: string;
  balance: number;
  nonce: number;
  tokens: Record<string, number>;
}

interface TokenInfo {
  address: string;
  symbol: string;
  name: string;
  creator: string;
  createdAt: number;
  totalSupply: number;
  distributed: number;
  poolRatio: number;
  distribution: 'creator' | 'mining' | 'split' | 'airdrop';
}

interface AMMPool {
  tokenAddress: string;
  btrReserve: number;
  tokenReserve: number;
}

interface Packet {
  type: string;
  data?: any;
  timestamp?: number;
}

// ============================================================
// ヘルパー
// ============================================================

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes: Uint8Array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function canonicalJSON(obj: unknown): string {
  if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const record = obj as Record<string, unknown>;
  const keys: string[] = Object.keys(record).sort();
  const pairs: string[] = keys.map(k => `${JSON.stringify(k)}:${canonicalJSON(record[k])}`);
  return '{' + pairs.join(',') + '}';
}

function log(category: string, message: string): void {
  const time: string = new Date().toISOString().slice(11, 19);
  console.log(`[${time}][${category}] ${message}`);
}

function computeBlockHash(block: Block): string {
  return sha256(
    block.previousHash +
    block.timestamp +
    block.nonce +
    block.difficulty +
    block.miner +
    block.reward +
    JSON.stringify(block.transactions)
  );
}

// ============================================================
// 状態管理
// ============================================================

const chain: Block[] = [];
const accounts: Map<string, Account> = new Map();
const tokens: Map<string, TokenInfo> = new Map();
const ammPools: Map<string, AMMPool> = new Map();
const pendingTxs: Transaction[] = [];
let commonRandom: string = '';
let totalMined: number = 0;
let currentDifficulty: number = 1;

// ============================================================
// アカウント管理
// ============================================================

function getAccount(address: string): Account {
  if (!accounts.has(address)) {
    accounts.set(address, {
      address,
      balance: 0,
      nonce: 0,
      tokens: {},
    });
  }
  return accounts.get(address)!;
}

// ★ アカウント保存ヘルパー
function saveAccount(account: Account): void {
  try {
    const filename = `./users/${account.address}.json`;
    writeFileSync(filename, JSON.stringify(account));
  } catch (e) {
    // 保存失敗は無視（定期保存で再試行）
  }
}

// ★ トークン保存ヘルパー
function saveToken(token: TokenInfo): void {
  try {
    const filename = `./tokens/${token.address}.json`;
    writeFileSync(filename, JSON.stringify(token));
  } catch (e) {
    // 保存失敗は無視（定期保存で再試行）
  }
}

function getTokenBalance(address: string, tokenAddress: string): number {
  const account: Account = getAccount(address);
  return account.tokens[tokenAddress] || 0;
}

// ============================================================
// ジェネシスブロック
// ============================================================

function createGenesisBlock(): GenesisBlock {
  const block: GenesisBlock = {
    height: 0,
    previousHash: '0x' + '0'.repeat(64),
    timestamp: Date.now(),
    nonce: 0,
    difficulty: 1,
    miner: '0x' + '0'.repeat(40),
    reward: 0,
    transactions: [],
    hash: '',
    config: CONFIG,
    message: 'Foooooooooooooooooooo物理班最高!YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA',
  };
  block.hash = computeBlockHash(block);
  return block;
}

// ============================================================
// トランザクション検証
// ============================================================

async function verifyTransaction(tx: Transaction): Promise<{ valid: boolean; error?: string }> {
  // 1. 公開鍵 → アドレス検証
  const expectedAddress: string = '0x' + sha256(tx.publicKey).slice(0, 40);
  if (expectedAddress !== tx.from) {
    return { valid: false, error: '公開鍵とアドレスが不一致' };
  }

  // 2. 署名検証
  const { signature, ...rest } = tx;
  const message: string = canonicalJSON(rest);
  try {
    const valid: boolean = await Ed25519.verify(
      hexToBytes(signature),
      new TextEncoder().encode(message),
      hexToBytes(tx.publicKey)
    );
    if (!valid) return { valid: false, error: '署名が無効' };
  } catch {
    return { valid: false, error: '署名検証エラー' };
  }

  // 3. タイムスタンプ
  if (Math.abs(Date.now() - tx.timestamp) > CONFIG.TIMESTAMP_TOLERANCE) {
    return { valid: false, error: 'タイムスタンプが範囲外' };
  }

  // 4. nonce
  const account: Account = getAccount(tx.from);
  if (tx.nonce !== account.nonce) {
    return { valid: false, error: `nonce不一致 (期待: ${account.nonce}, 受信: ${tx.nonce})` };
  }

  // 5. 手数料
  if (tx.fee !== CONFIG.GAS_FEE) {
    return { valid: false, error: 'ガス代が不正' };
  }

  // 6. 残高チェック
  if (account.balance < tx.fee) {
    return { valid: false, error: 'ガス代の残高不足' };
  }

  // 7. type別チェック
  switch (tx.type) {
    case 'transfer': {
      if (!tx.to || tx.amount === undefined || tx.amount <= 0) {
        return { valid: false, error: 'transfer: 宛先または金額が不正' };
      }
      if (tx.token === BTR_ADDRESS) {
        if (account.balance < tx.amount + tx.fee) {
          return { valid: false, error: 'BTR残高不足' };
        }
      }
      break;
    }
    case 'token_transfer': {
      if (!tx.to || tx.amount === undefined || tx.amount <= 0) {
        return { valid: false, error: 'token_transfer: 宛先または金額が不正' };
      }
      const tokenBal: number = getTokenBalance(tx.from, tx.token);
      if (tokenBal < tx.amount) {
        return { valid: false, error: 'トークン残高不足' };
      }
      break;
    }
    case 'create_token': {
      if (!tx.data?.name || !tx.data?.symbol || !tx.data?.totalSupply || tx.data.totalSupply <= 0) {
        return { valid: false, error: 'create_token: データが不正' };
      }
      if (account.balance < CONFIG.TOKEN_CREATION_FEE + tx.fee) {
        return { valid: false, error: 'トークン作成費の残高不足' };
      }
      break;
    }
    case 'swap': {
      if (!tx.data?.tokenIn || !tx.data?.tokenOut || !tx.data?.amountIn || tx.data.amountIn <= 0) {
        return { valid: false, error: 'swap: データが不正' };
      }
      if (tx.data.tokenIn === tx.data.tokenOut) {
        return { valid: false, error: 'swap: 同一トークン間のスワップ不可' };
      }
      // 残高チェック
      if (tx.data.tokenIn === BTR_ADDRESS) {
        if (account.balance < tx.data.amountIn + tx.fee) {
          return { valid: false, error: 'swap: BTR残高不足' };
        }
      } else {
        const tokenBal: number = getTokenBalance(tx.from, tx.data.tokenIn);
        if (tokenBal < tx.data.amountIn) {
          return { valid: false, error: 'swap: トークン残高不足' };
        }
      }
      // AMMプール存在チェック
      if (tx.data.tokenIn !== BTR_ADDRESS && !ammPools.has(tx.data.tokenIn)) {
        return { valid: false, error: 'swap: 入力トークンのプールが存在しない' };
      }
      if (tx.data.tokenOut !== BTR_ADDRESS && !ammPools.has(tx.data.tokenOut)) {
        return { valid: false, error: 'swap: 出力トークンのプールが存在しない' };
      }
      break;
    }
    case 'rename_token': {
      if (!tx.data?.newName || !tx.token) {
        return { valid: false, error: 'rename_token: データが不正' };
      }
      if (account.balance < CONFIG.TOKEN_RENAME_FEE + tx.fee) {
        return { valid: false, error: 'トークン名変更費の残高不足' };
      }
      const token: TokenInfo | undefined = tokens.get(tx.token);
      if (!token || token.creator !== tx.publicKey) {
        return { valid: false, error: 'トークン作成者のみ名前変更可能' };
      }
      break;
    }
    default:
      return { valid: false, error: `不明なトランザクションタイプ: ${tx.type}` };
  }

  return { valid: true };
}

// ============================================================
// トランザクション適用
// ============================================================

function applyTransaction(tx: Transaction, minerAddress: string): void {
  const sender: Account = getAccount(tx.from);
  const miner: Account = getAccount(minerAddress);
  const isSelfMining = (tx.from === minerAddress);

  // ガス代（自己マイニングの場合は相殺されるので何もしない）
  if (!isSelfMining) {
    sender.balance -= tx.fee;
    miner.balance += tx.fee;
  }
  sender.nonce++;

  switch (tx.type) {
    case 'transfer': {
      const receiver: Account = getAccount(tx.to!);
      if (tx.token === BTR_ADDRESS) {
        sender.balance -= tx.amount!;
        receiver.balance += tx.amount!;
      }
      break;
    }
    case 'token_transfer': {
      const receiver: Account = getAccount(tx.to!);
      const senderBal: number = sender.tokens[tx.token] || 0;
      sender.tokens[tx.token] = senderBal - tx.amount!;
      const receiverBal: number = receiver.tokens[tx.token] || 0;
      receiver.tokens[tx.token] = receiverBal + tx.amount!;
      break;
    }
    case 'create_token': {
      sender.balance -= CONFIG.TOKEN_CREATION_FEE;
      if (!isSelfMining) {
        miner.balance += CONFIG.TOKEN_CREATION_FEE;
      }

      const tokenAddress: string = '0x' + sha256(tx.signature + tx.timestamp).slice(0, 16);
      const poolRatio: number = tx.data!.poolRatio || 0;
      const totalSupply: number = tx.data!.totalSupply!;

      const tokenInfo: TokenInfo = {
        address: tokenAddress,
        symbol: tx.data!.symbol!,
        name: tx.data!.name!,
        creator: tx.publicKey,
        createdAt: tx.timestamp,
        totalSupply,
        distributed: totalSupply,
        poolRatio,
        distribution: tx.data!.distribution || 'creator',
      };
      tokens.set(tokenAddress, tokenInfo);

      // 配布
      const creatorAmount: number = totalSupply * (1 - poolRatio);
      const poolAmount: number = totalSupply * poolRatio;

      if (creatorAmount > 0) {
        sender.tokens[tokenAddress] = (sender.tokens[tokenAddress] || 0) + creatorAmount;
      }

      // AMM プール作成
      if (poolAmount > 0) {
        ammPools.set(tokenAddress, {
          tokenAddress,
          btrReserve: CONFIG.TOKEN_CREATION_FEE,
          tokenReserve: poolAmount,
        });
      }
      break;
    }
    case 'swap': {
      executeSwap(tx);
      break;
    }
    case 'rename_token': {
      sender.balance -= CONFIG.TOKEN_RENAME_FEE;
      if (!isSelfMining) {
        miner.balance += CONFIG.TOKEN_RENAME_FEE;
      }
      const token: TokenInfo | undefined = tokens.get(tx.token);
      if (token) {
        token.name = tx.data!.newName!;
      }
      break;
    }
  }

  // アカウント保存はsaveState()で一括処理
}

// ============================================================
// AMM
// ============================================================

function getAMMRate(tokenAddress: string): number {
  const pool: AMMPool | undefined = ammPools.get(tokenAddress);
  if (!pool || pool.tokenReserve === 0) return 0;
  return pool.btrReserve / pool.tokenReserve;
}

function getFluctuatedRate(tokenAddress: string, minute: number): number {
  const base: number = getAMMRate(tokenAddress);
  if (base === 0 || !commonRandom) return base;

  const seed: string = sha256(commonRandom + tokenAddress + minute);
  const fluctuation: number = parseInt(seed.slice(0, 8), 16);
  const change: number = (fluctuation % 3000 - 1500) / 10000;
  return base * (1 + change);
}

function executeSwap(tx: Transaction): void {
  const tokenIn: string = tx.data!.tokenIn!;
  const tokenOut: string = tx.data!.tokenOut!;
  const amountIn: number = tx.data!.amountIn!;
  const sender: Account = getAccount(tx.from);

  if (tokenIn === BTR_ADDRESS) {
    // BTR → Token
    const pool: AMMPool | undefined = ammPools.get(tokenOut);
    if (!pool) return;
    if (sender.balance < amountIn) return;
    sender.balance -= amountIn;
    const amountOut: number = (amountIn * pool.tokenReserve) / (pool.btrReserve + amountIn);
    pool.btrReserve += amountIn;
    pool.tokenReserve -= amountOut;
    sender.tokens[tokenOut] = (sender.tokens[tokenOut] || 0) + amountOut;
  } else if (tokenOut === BTR_ADDRESS) {
    // Token → BTR
    const pool: AMMPool | undefined = ammPools.get(tokenIn);
    if (!pool) return;
    const senderBal: number = sender.tokens[tokenIn] || 0;
    if (senderBal < amountIn) return;
    sender.tokens[tokenIn] = senderBal - amountIn;
    const amountOut: number = (amountIn * pool.btrReserve) / (pool.tokenReserve + amountIn);
    pool.tokenReserve += amountIn;
    pool.btrReserve -= amountOut;
    sender.balance += amountOut;
  } else {
    // Token → Token (TokenA → BTR → TokenB)
    const poolA: AMMPool | undefined = ammPools.get(tokenIn);
    const poolB: AMMPool | undefined = ammPools.get(tokenOut);
    if (!poolA || !poolB) return;
    const senderBal: number = sender.tokens[tokenIn] || 0;
    if (senderBal < amountIn) return;
    sender.tokens[tokenIn] = senderBal - amountIn;
    // TokenA → BTR
    const btrAmount: number = (amountIn * poolA.btrReserve) / (poolA.tokenReserve + amountIn);
    poolA.tokenReserve += amountIn;
    poolA.btrReserve -= btrAmount;
    // BTR → TokenB
    const amountOut: number = (btrAmount * poolB.tokenReserve) / (poolB.btrReserve + btrAmount);
    poolB.btrReserve += btrAmount;
    poolB.tokenReserve -= amountOut;
    sender.tokens[tokenOut] = (sender.tokens[tokenOut] || 0) + amountOut;
  }
}

// ============================================================
// ブロック検証
// ============================================================

function verifyBlock(block: Block): { valid: boolean; error?: string } {
  // 難易度は正の整数であること
  if (block.difficulty < 1 || !Number.isInteger(block.difficulty)) {
    return { valid: false, error: `難易度が不正: ${block.difficulty}` };
  }

  // ハッシュ検証
  const expectedHash: string = computeBlockHash(block);
  if (block.hash !== expectedHash) {
    return { valid: false, error: 'ブロックハッシュ不一致' };
  }

  // PoW検証（ブロック自身の難易度で）
  if (!block.hash.startsWith('0'.repeat(block.difficulty))) {
    return { valid: false, error: 'PoW条件を満たしていない' };
  }

  // チェーン連結
  if (chain.length > 0) {
    const prev: Block = chain[chain.length - 1];
    if (block.previousHash !== prev.hash) {
      return { valid: false, error: 'previousHash不一致' };
    }
    if (block.height !== prev.height + 1) {
      return { valid: false, error: 'height不一致' };
    }
  }

  // ブロックサイズ
  const size: number = Buffer.byteLength(JSON.stringify(block.transactions));
  if (size > CONFIG.MAX_BLOCK_SIZE) {
    return { valid: false, error: 'ブロックサイズ超過' };
  }

  // 報酬チェック
  if (block.reward < CONFIG.BLOCK_REWARD_MIN || block.reward > CONFIG.BLOCK_REWARD_MAX) {
    return { valid: false, error: '報酬が範囲外' };
  }

  return { valid: true };
}

// ============================================================
// ブロック適用
// ============================================================

function applyBlock(block: Block): void {
  // マイニング報酬
  if (block.height > 0 && totalMined < CONFIG.TOTAL_SUPPLY) {
    const miner: Account = getAccount(block.miner);
    const reward: number = Math.min(block.reward, CONFIG.TOTAL_SUPPLY - totalMined);
    miner.balance += reward;
    totalMined += reward;
  }

  // トランザクション適用
  for (const tx of block.transactions) {
    applyTransaction(tx, block.miner);
  }

  // マイニングトークン配布
  for (const [, token] of tokens) {
    if (token.distribution === 'mining' && token.distributed < token.totalSupply) {
      const miner: Account = getAccount(block.miner);
      const tokenReward: number = Math.min(100, token.totalSupply - token.distributed);
      miner.tokens[token.address] = (miner.tokens[token.address] || 0) + tokenReward;
      token.distributed += tokenReward;
    }
  }

  chain.push(block);

  // ★ 新ブロックを即座にファイル保存
  try {
    const filename = `./chain/${block.height.toString().padStart(64, '0')}.json`;
    writeFileSync(filename, JSON.stringify(block));
  } catch (e) {
    log('Save', `ブロック保存失敗: ${e}`);
  }

  // 難易度調整
  adjustDifficulty();

  // pending から適用済みTxを除去
  const txSigs: Set<string> = new Set(block.transactions.map(tx => tx.signature));
  const remaining: Transaction[] = pendingTxs.filter(tx => !txSigs.has(tx.signature));
  pendingTxs.length = 0;
  pendingTxs.push(...remaining);
  
  // saveState()は呼ばない（定期保存のみ）
}

// ============================================================
// 難易度調整
// ============================================================

function adjustDifficulty(): void {
  if (chain.length < CONFIG.DIFFICULTY_WINDOW + 1) return;

  const recent: Block[] = chain.slice(-CONFIG.DIFFICULTY_WINDOW);
  const totalTime: number = recent[recent.length - 1].timestamp - recent[0].timestamp;
  const avgTime: number = totalTime / (recent.length - 1);
  const targetMs: number = CONFIG.BLOCK_TIME * 1000;

  if (avgTime < targetMs * 0.85) {
    currentDifficulty++;
    log('Difficulty', `難易度UP: ${currentDifficulty} (平均 ${(avgTime / 1000).toFixed(1)}秒, 目標 ${CONFIG.BLOCK_TIME}秒)`);
  } else if (avgTime > targetMs * 1.15 && currentDifficulty > 1) {
    currentDifficulty--;
    log('Difficulty', `難易度DOWN: ${currentDifficulty} (平均 ${(avgTime / 1000).toFixed(1)}秒, 目標 ${CONFIG.BLOCK_TIME}秒)`);
  }
}

// ============================================================
// ブロック報酬算出（分散乱数ベース）
// ============================================================

function calculateReward(height: number): number {
  if (!commonRandom) return 100;
  if (totalMined >= CONFIG.TOTAL_SUPPLY) return 0;

  const seed: string = sha256(commonRandom + 'BTR_REWARD' + height);
  const value: number = parseInt(seed.slice(0, 8), 16);
  const reward: number = CONFIG.BLOCK_REWARD_MIN + (value % (CONFIG.BLOCK_REWARD_MAX - CONFIG.BLOCK_REWARD_MIN + 1));
  return Math.min(reward, CONFIG.TOTAL_SUPPLY - totalMined);
}

// ============================================================
// フォーク選択
// ============================================================

function selectChain(otherChain: Block[]): boolean {
  if (otherChain.length <= chain.length) {
    if (otherChain.length === chain.length) {
      const myDiff: number = chain.reduce((sum, b) => sum + b.difficulty, 0);
      const otherDiff: number = otherChain.reduce((sum, b) => sum + b.difficulty, 0);
      if (otherDiff <= myDiff) return false;
    } else {
      return false;
    }
  }

  // 他チェーンが長いまたは累積難易度が高い → 巻き戻し & 適用
  log('Chain', `フォーク検出: 現在=${chain.length}, 受信=${otherChain.length}`);
  rebuildState(otherChain);
  return true;
}

function rebuildState(newChain: Block[], silent: boolean = true): void {
  // 全リセット
  chain.length = 0;
  accounts.clear();
  tokens.clear();
  ammPools.clear();
  totalMined = 0;
  currentDifficulty = 1;

  // 再適用（サイレントモード）
  const originalApplyBlock = applyBlock;
  if (silent) {
    // サイレントモード: ログを抑制
    (globalThis as any).__rebuildingSilent = true;
  }
  
  for (const block of newChain) {
    applyBlock(block);
  }
  
  if (silent) {
    delete (globalThis as any).__rebuildingSilent;
  }
}

// ============================================================
// 永続化
// ============================================================

function saveState(): void {
  try {
    // ディレクトリ作成
    if (!existsSync('./chain')) {
      fs.mkdirSync('./chain', { recursive: true });
    }
    if (!existsSync('./users')) {
      fs.mkdirSync('./users', { recursive: true });
    }
    if (!existsSync('./tokens')) {
      fs.mkdirSync('./tokens', { recursive: true });
    }

    // チェーン保存: 各ブロックを個別ファイルに
    for (const block of chain) {
      const filename = `./chain/${block.height.toString().padStart(64, '0')}.json`;
      writeFileSync(filename, JSON.stringify(block));
    }

    // アカウント保存: 各アカウントを個別ファイルに
    for (const [address, account] of accounts) {
      const filename = `./users/${address}.json`;
      writeFileSync(filename, JSON.stringify(account));
    }

    // トークン保存: 各トークンを個別ファイルに
    for (const [address, token] of tokens) {
      const filename = `./tokens/${address}.json`;
      writeFileSync(filename, JSON.stringify(token));
    }

    // メタデータ保存
    const meta = {
      chainLength: chain.length,
      accountCount: accounts.size,
      tokenCount: tokens.size,
      lastSaved: Date.now()
    };
    writeFileSync('./state_meta.json', JSON.stringify(meta, null, 2));

  } catch (e: unknown) {
    const msg: string = e instanceof Error ? e.message : String(e);
    log('Save', `保存失敗: ${msg}`);
  }
}

function loadState(): void {
  try {
    // ディレクトリ作成
    if (!existsSync('./chain')) {
      fs.mkdirSync('./chain', { recursive: true });
    }
    if (!existsSync('./users')) {
      fs.mkdirSync('./users', { recursive: true });
    }
    if (!existsSync('./tokens')) {
      fs.mkdirSync('./tokens', { recursive: true });
    }

    // メタデータ読み込み
    let chainLength = 0;
    if (existsSync('./state_meta.json')) {
      const meta = JSON.parse(readFileSync('./state_meta.json', 'utf-8'));
      chainLength = meta.chainLength || 0;
    }

    if (chainLength > 0) {
      // チェーン読み込み: 各ブロックファイルから
      const blocks: Block[] = [];
      for (let height = 0; height < chainLength; height++) {
        const filename = `./chain/${height.toString().padStart(64, '0')}.json`;
        if (existsSync(filename)) {
          const block: Block = JSON.parse(readFileSync(filename, 'utf-8'));
          blocks.push(block);
        } else {
          log('Load', `⚠ ブロックファイル欠落: height ${height}`);
        }
      }
      
      if (blocks.length > 0) {
        rebuildState(blocks);
        log('Load', `チェーン読み込み: ${chain.length}ブロック (ファイルベース)`);
      } else {
        // ジェネシスブロック
        const genesis: GenesisBlock = createGenesisBlock();
        chain.push(genesis);
        log('Load', 'ジェネシスブロック作成');
      }
    } else {
      // 旧形式からの移行チェック
      if (existsSync(CONFIG.CHAIN_FILE)) {
        log('Load', '旧形式検出: 移行中...');
        const data: Block[] = JSON.parse(readFileSync(CONFIG.CHAIN_FILE, 'utf-8'));
        rebuildState(data);
        saveState(); // 新形式で保存
        log('Load', `チェーン移行完了: ${chain.length}ブロック`);
      } else {
        // ジェネシスブロック
        const genesis: GenesisBlock = createGenesisBlock();
        chain.push(genesis);
        log('Load', 'ジェネシスブロック作成');
      }
    }
  } catch (e: unknown) {
    const msg: string = e instanceof Error ? e.message : String(e);
    log('Load', `読み込み失敗: ${msg}`);
    const genesis: GenesisBlock = createGenesisBlock();
    chain.push(genesis);
  }
}

// ============================================================
// チェーン同期
// ============================================================

let syncBuffer: Block[] = [];
let syncExpectedFrom: number = 0;
let syncTimer: ReturnType<typeof setTimeout> | null = null;
let isSyncing: boolean = false;

function startSyncTimeout(): void {
  if (syncTimer) clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    if (isSyncing) {
      log('Sync', 'タイムアウト — フォールバック: シードに直接チェーン要求');
      isSyncing = false;
      syncBuffer = [];
      // フォールバック: シードサーバー経由で自分からチェーンを要求
      sendToSeed({ type: 'request_chain', data: { fromHeight: chain.length } });
      // 2回目のタイムアウト
      syncTimer = setTimeout(() => {
        if (chain.length <= 1) {
          log('Sync', '同期失敗、ジェネシスから開始');
        }
        syncTimer = null;
      }, 15000);
    }
  }, 10000);
}

function finishSync(): void {
  isSyncing = false;
  if (syncTimer) { clearTimeout(syncTimer); syncTimer = null; }
  saveState();
  
  // ★ メタデータ更新
  try {
    const meta = {
      chainLength: chain.length,
      accountCount: accounts.size,
      tokenCount: tokens.size,
      lastSaved: Date.now()
    };
    writeFileSync('./state_meta.json', JSON.stringify(meta, null, 2));
  } catch (e) {
    log('Save', `メタデータ保存失敗: ${e}`);
  }
  
  sendToSeed({ type: 'height', data: { height: chain.length, difficulty: currentDifficulty } });
  log('Sync', `同期完了: ${chain.length}ブロック, 難易度=${currentDifficulty}`);
}

// ============================================================
// シードノード接続
// ============================================================

let seedSocket: Socket | null = null;
let seedBuffer: string = '';

function connectToSeed(): void {
  log('Net', `シードノードに接続中: ${CONFIG.SEED_HOST}:${CONFIG.SEED_PORT}`);

  seedSocket = connect(CONFIG.SEED_PORT, CONFIG.SEED_HOST, () => {
    log('Net', '接続成功');

    // ノード登録
    sendToSeed({
      type: 'register',
      data: { chainHeight: chain.length, difficulty: currentDifficulty }
    });

    // 同期待ちタイマー開始
    isSyncing = true;
    startSyncTimeout();
  });

  seedSocket.on('data', (data: Buffer) => {
    seedBuffer += data.toString();
    const parts: string[] = seedBuffer.split(DELIMITER);
    seedBuffer = parts.pop() || '';

    for (const part of parts) {
      if (!part.trim()) continue;
      try {
        const packet: Packet = JSON.parse(part);
        handlePacket(packet);
      } catch {
        // パース失敗
      }
    }
  });

  seedSocket.on('close', () => {
    log('Net', 'シードノード切断、3秒後に再接続');
    seedSocket = null;
    setTimeout(connectToSeed, 3000);
  });

  seedSocket.on('error', (err: Error) => {
    log('Net', `接続エラー: ${err.message}`);
  });
}

function sendToSeed(packet: Packet): void {
  if (seedSocket && !seedSocket.destroyed) {
    seedSocket.write(JSON.stringify(packet) + DELIMITER);
  }
}

// ============================================================
// パケットハンドリング
// ============================================================

async function handlePacket(packet: Packet): Promise<void> {
  switch (packet.type) {
    // --- ハートビート ---
    case 'ping':
      sendToSeed({ type: 'pong' });
      break;

    // --- ノードリスト ---
    case 'node_list': {
      const nodes = packet.data?.nodes || [];
      log('Net', `ノードリスト受信: ${nodes.length}台`);
      // 自分しかいない or 自分が最長 → 同期完了
      if (isSyncing && nodes.length <= 1) {
        log('Sync', '他ノードなし、同期スキップ');
        finishSync();
      }
      break;
    }

    case 'new_node':
      log('Net', `新ノード参加: ${packet.data?.id}`);
      break;

    case 'node_left':
      log('Net', `ノード離脱: ${packet.data?.id}`);
      break;

    // --- ブロック受信 ---
    case 'block_broadcast': {
      const { minerId: _mid, ...blockOnly } = packet.data;
      const block: Block = blockOnly;
      const result = verifyBlock(block);
      if (result.valid) {
        applyBlock(block);
        log('Block', `ブロック適用: #${block.height} by ${block.miner.slice(0, 10)}... (${block.transactions.length}tx)`);
        saveState();
        // クライアントに結果を返す（難易度・最新ハッシュ含む）
        sendToSeed({
          type: 'block_accepted',
          data: {
            height: chain.length,
            hash: block.hash,
            difficulty: currentDifficulty,
            reward: calculateReward(chain.length),
            minerId: packet.data?.minerId,
          }
        });
      } else {
        log('Block', `ブロック拒否: ${result.error}`);
        sendToSeed({
          type: 'block_rejected',
          data: {
            error: result.error,
            difficulty: currentDifficulty,
            height: chain.length,
            hash: chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64),
            minerId: packet.data?.minerId,
          }
        });
      }
      break;
    }

    // --- トランザクション受信 ---
    case 'tx': {
      const clientId: string | undefined = packet.data?.clientId;
      // clientIdを除去してトランザクションだけにする
      const { clientId: _cid, ...txOnly } = packet.data;
      const tx: Transaction = txOnly;
      const result = await verifyTransaction(tx);

      if (result.valid) {
        pendingTxs.push(tx);
        log('Tx', `受付: ${tx.type} from ${tx.from.slice(0, 10)}...`);

        // 他ノードにも伝播
        sendToSeed({ type: 'tx_broadcast', data: tx });

        // 結果返答
        if (clientId) {
          sendToSeed({ type: 'tx_result', data: { clientId, success: true, txType: tx.type } });
        }
      } else {
        log('Tx', `拒否: ${result.error}`);
        if (clientId) {
          sendToSeed({ type: 'tx_result', data: { clientId, success: false, error: result.error } });
        }
      }
      break;
    }

    case 'tx_broadcast': {
      const tx: Transaction = packet.data;
      const result = await verifyTransaction(tx);
      if (result.valid) {
        // 重複チェック
        const exists: boolean = pendingTxs.some(p => p.signature === tx.signature);
        if (!exists) {
          pendingTxs.push(tx);
        }
      }
      break;
    }

    // --- クライアントからの照会 ---
    case 'get_balance': {
      const clientId: string = packet.data?.clientId;
      const address: string = packet.data?.address;
      const account: Account = getAccount(address);
      const adminRequest: boolean = packet.data?.adminRequest || false;
      
      if (adminRequest) {
        sendToSeed({
          type: 'admin_account',
          data: { clientId, found: true, account: { address: account.address, balance: account.balance, nonce: account.nonce, tokens: account.tokens } }
        });
      } else {
        sendToSeed({
          type: 'balance',
          data: { clientId, address, balance: account.balance, nonce: account.nonce, tokens: account.tokens }
        });
      }
      break;
    }

    case 'get_height': {
      const clientId: string = packet.data?.clientId;
      const latestHash: string = chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64);
      sendToSeed({
        type: 'height',
        data: { clientId, height: chain.length, difficulty: currentDifficulty, latestHash }
      });
      break;
    }

    case 'get_block_template': {
      const clientId: string = packet.data?.clientId;
      const miner: string = packet.data?.miner || '';
      const latestHash: string = chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64);
      const reward: number = calculateReward(chain.length);
      sendToSeed({
        type: 'block_template',
        data: {
          clientId,
          height: chain.length,
          previousHash: latestHash,
          difficulty: currentDifficulty,
          reward,
          transactions: pendingTxs,
          miner,
        }
      });
      break;
    }

    case 'get_chain': {
      const clientId: string = packet.data?.clientId;
      let from: number = packet.data?.from || 0;
      let to: number = packet.data?.to || chain.length;
      const isAdmin: boolean = packet.data?.admin || false;
      
      // 負の値の場合は最新から取得
      if (from < 0) {
        from = Math.max(0, chain.length + from);
        to = chain.length;
      }
      
      const chunk: Block[] = chain.slice(from, to);
      
      if (isAdmin) {
        sendToSeed({
          type: 'admin_blocks',
          data: { clientId, blocks: chunk }
        });
      } else {
        sendToSeed({
          type: 'chain_chunk',
          data: { clientId, from, to, blocks: chunk }
        });
      }
      break;
    }

    case 'get_token': {
      const clientId: string = packet.data?.clientId;
      const tokenAddress: string = packet.data?.address;
      const token: TokenInfo | undefined = tokens.get(tokenAddress);
      sendToSeed({
        type: 'token_info',
        data: { clientId, token: token || null }
      });
      break;
    }

    case 'get_tokens_list': {
      const clientId: string = packet.data?.clientId;
      const list = Array.from(tokens.values()).map(t => ({
        address: t.address, symbol: t.symbol, name: t.name, totalSupply: t.totalSupply
      }));
      sendToSeed({
        type: 'tokens_list',
        data: { clientId, tokens: list }
      });
      break;
    }

    case 'get_rate': {
      const clientId: string = packet.data?.clientId;
      const tokenAddress: string = packet.data?.address;
      const minute: number = Math.floor(Date.now() / 60000);
      const rate: number = getFluctuatedRate(tokenAddress, minute);
      sendToSeed({
        type: 'rate',
        data: { clientId, tokenAddress, rate, minute }
      });
      break;
    }

    // --- 誰でもアクセス可能 ---
    case 'get_mempool': {
      const clientId: string = packet.data?.clientId;
      const isAdmin: boolean = packet.data?.admin || false;
      
      if (isAdmin) {
        sendToSeed({
          type: 'admin_mempool',
          data: { 
            clientId, 
            count: pendingTxs.length,
            transactions: pendingTxs.slice(0, 50)
          }
        });
      } else {
        sendToSeed({
          type: 'mempool',
          data: { 
            clientId, 
            count: pendingTxs.length,
            transactions: pendingTxs.slice(0, 50)
          }
        });
      }
      break;
    }

    case 'get_recent_transactions': {
      const clientId: string = packet.data?.clientId;
      const limit: number = packet.data?.limit || 50;
      const isAdmin: boolean = packet.data?.admin || false;
      
      // 最新のブロックからトランザクションを収集
      const recentTxs: Transaction[] = [];
      for (let i = chain.length - 1; i >= 0 && recentTxs.length < limit; i--) {
        const block: Block = chain[i];
        for (const tx of block.transactions) {
          if (recentTxs.length >= limit) break;
          recentTxs.push(tx);
        }
      }
      
      if (isAdmin) {
        sendToSeed({
          type: 'admin_transactions',
          data: { clientId, transactions: recentTxs }
        });
      } else {
        sendToSeed({
          type: 'transactions',
          data: { clientId, transactions: recentTxs }
        });
      }
      break;
    }
    
    case 'get_block': {
      const clientId: string = packet.data?.clientId;
      const height: number = packet.data?.height;
      
      if (height >= 0 && height < chain.length) {
        sendToSeed({
          type: 'block',
          data: { clientId, block: chain[height] }
        });
      } else {
        sendToSeed({
          type: 'block',
          data: { clientId, block: null, error: 'ブロックが見つかりません' }
        });
      }
      break;
    }

    // --- 管理者コマンド (root only) ---
    case 'admin_mint': {
      const { address, amount, clientId } = packet.data;
      
      // Validate amount
      if (typeof amount !== 'number' || amount <= 0 || !isFinite(amount)) {
        sendToSeed({
          type: 'admin_mint_result',
          data: { clientId, success: false, message: '無効な金額です' }
        });
        break;
      }
      
      // Validate amount is within reasonable bounds (max 1 billion BTR per mint)
      if (amount > 1_000_000_000) {
        sendToSeed({
          type: 'admin_mint_result',
          data: { clientId, success: false, message: '金額が大きすぎます（最大: 1,000,000,000 BTR）' }
        });
        break;
      }
      
      log('Admin', `コイン発行実行: ${address} に ${amount} BTR`);
      
      const account = getAccount(address);
      account.balance += amount;
      saveState();
      
      sendToSeed({
        type: 'admin_mint_result',
        data: { clientId, success: true, address, amount, newBalance: account.balance }
      });
      break;
    }

    case 'admin_distribute': {
      const { distributions, clientId } = packet.data;
      log('Admin', `一括配給実行: ${distributions.length} 件`);
      
      // Validate all distributions first
      for (const dist of distributions) {
        const { amount } = dist;
        if (typeof amount !== 'number' || amount <= 0 || !isFinite(amount)) {
          sendToSeed({
            type: 'admin_distribute_result',
            data: { clientId, success: false, message: '無効な金額が含まれています' }
          });
          return;
        }
        if (amount > 1_000_000_000) {
          sendToSeed({
            type: 'admin_distribute_result',
            data: { clientId, success: false, message: '金額が大きすぎます（最大: 1,000,000,000 BTR）' }
          });
          return;
        }
      }
      
      const results = [];
      for (const dist of distributions) {
        const { address, amount } = dist;
        const account = getAccount(address);
        account.balance += amount;
        results.push({ address, amount, newBalance: account.balance });
      }
      saveState();
      
      sendToSeed({
        type: 'admin_distribute_result',
        data: { clientId, success: true, count: results.length, results }
      });
      break;
    }

    case 'admin_clear_mempool': {
      const { clientId } = packet.data;
      const count = pendingTxs.length;
      log('Admin', `Mempool全消去: ${count} 件のトランザクションを削除`);
      
      pendingTxs.length = 0;
      
      sendToSeed({
        type: 'admin_clear_mempool_result',
        data: { clientId, success: true, count }
      });
      break;
    }

    case 'admin_remove_tx': {
      const { signature, clientId } = packet.data;
      log('Admin', `トランザクション削除: ${signature.slice(0, 16)}...`);
      
      const index = pendingTxs.findIndex(tx => tx.signature === signature);
      let success = false;
      
      if (index !== -1) {
        pendingTxs.splice(index, 1);
        success = true;
        log('Admin', `トランザクション削除成功`);
      } else {
        log('Admin', `トランザクションが見つかりません`);
      }
      
      sendToSeed({
        type: 'admin_remove_tx_result',
        data: { clientId, success, signature }
      });
      break;
    }

    // --- 分散乱数 ---
    case 'random_request': {
      // 乱数生成 & コミット
      const myRandom: string = randomBytes(32).toString('hex');
      const commit: string = sha256(myRandom);
      // 一時保存（revealで使う）
      (global as any).__btrRandomValue = myRandom;
      sendToSeed({ type: 'random_commit', data: { hash: commit } });
      break;
    }

    case 'random_reveal_request': {
      const myRandom: string = (global as any).__btrRandomValue || '';
      sendToSeed({ type: 'random_reveal', data: { value: myRandom } });
      break;
    }

    case 'random_result': {
      commonRandom = packet.data?.random || '';
      log('Random', `共通乱数受信: ${commonRandom.slice(0, 16)}...`);
      break;
    }

    // --- チェーン同期 ---
    case 'send_chain_to': {
      // シードサーバーから依頼: 新ノード向けにチェーンを送る
      const targetNodeId: string = packet.data?.targetNodeId;
      const fromHeight: number = packet.data?.fromHeight || 0;
      if (chain.length > fromHeight) {
        const CHUNK_SIZE = 50;
        const totalChunks = Math.ceil((chain.length - fromHeight) / CHUNK_SIZE);
        let chunkIndex = 0;
        for (let i = fromHeight; i < chain.length; i += CHUNK_SIZE) {
          chunkIndex++;
          const chunk: Block[] = chain.slice(i, Math.min(i + CHUNK_SIZE, chain.length));
          sendToSeed({
            type: 'chain_sync',
            data: {
              targetNodeId,
              blocks: chunk,
              chunkIndex,
              totalChunks,
              totalHeight: chain.length,
            }
          });
        }
        log('Sync', `チェーン送信: → ${targetNodeId} (${fromHeight}〜${chain.length}, ${totalChunks}チャンク)`);
      }
      break;
    }

    case 'chain_sync': {
      const blocks: Block[] = packet.data?.blocks;
      if (!blocks || blocks.length === 0) break;

      const chunkIndex: number = packet.data?.chunkIndex || 1;
      const totalChunks: number = packet.data?.totalChunks || 1;
      const totalHeight: number = packet.data?.totalHeight || 0;

      log('Sync', `チャンク受信: ${chunkIndex}/${totalChunks} (${blocks.length}ブロック, height ${blocks[0].height}〜${blocks[blocks.length - 1].height})`);

      // バッファに追加
      syncBuffer.push(...blocks);

      // タイムアウトリセット
      if (syncTimer) clearTimeout(syncTimer);
      startSyncTimeout();

      // 全チャンク受信完了チェック
      if (chunkIndex >= totalChunks || syncBuffer.length >= totalHeight) {
        log('Sync', `全チャンク受信完了: ${syncBuffer.length}ブロック`);
        
        // ソート（念のため）
        syncBuffer.sort((a, b) => a.height - b.height);

        if (syncBuffer.length > chain.length) {
          if (syncBuffer[0].height === 0) {
            selectChain(syncBuffer);
          } else if (syncBuffer[0].height <= chain.length) {
            const merged = [...chain.slice(0, syncBuffer[0].height), ...syncBuffer];
            selectChain(merged);
          }
        }
        syncBuffer = [];
        finishSync();
      }
      break;
    }

    case 'chain_sync_response': {
      // フォールバック: シードから直接チェーンを受信
      const blocks: Block[] = packet.data?.blocks;
      if (!blocks || blocks.length === 0) {
        log('Sync', 'フォールバック応答: ブロックなし');
        finishSync();
        break;
      }
      log('Sync', `フォールバック受信: ${blocks.length}ブロック`);
      blocks.sort((a, b) => a.height - b.height);
      if (blocks.length > chain.length) {
        if (blocks[0].height === 0) {
          selectChain(blocks);
        } else if (blocks[0].height <= chain.length) {
          const merged = [...chain.slice(0, blocks[0].height), ...blocks];
          selectChain(merged);
        }
      }
      finishSync();
      break;
    }

    case 'send_chain_direct': {
      // フォールバック: シードから直接依頼 — チャンク分割せず一括送信
      const targetNodeId: string = packet.data?.targetNodeId;
      const fromHeight: number = packet.data?.fromHeight || 0;
      if (chain.length > fromHeight) {
        const blocks: Block[] = chain.slice(fromHeight);
        sendToSeed({
          type: 'chain_sync_direct',
          data: { targetNodeId, blocks }
        });
        log('Sync', `フォールバック送信: → ${targetNodeId} (${blocks.length}ブロック)`);
      }
      break;
    }

    // --- アップデート ---
    case 'update': {
      log('Update', `アップデート受信: v${packet.data?.version}`);
      // ランチャーに転送
      if (process.send) {
        process.send({ type: 'update', data: packet.data });
      }
      break;
    }

    // --- trusted_keys同期 ---
    case 'sync_trusted_keys': {
      writeFileSync('./trusted_keys.json', JSON.stringify(packet.data, null, 2));
      log('Trust', 'trusted_keys.json 同期');
      break;
    }

    case 'sync_needed': {
      // シードサーバーから「遅れてるから同期して」と言われた
      log('Sync', `同期要求受信: 現在=${chain.length}, ネットワーク最長=${packet.data?.bestHeight || '?'}`);
      if (!isSyncing) {
        isSyncing = true;
        syncBuffer = [];
        startSyncTimeout();
      }
      break;
    }

    default:
      // 未知のパケットは無視
      break;
  }
}

// ============================================================
// 定期処理
// ============================================================

function startPeriodicTasks(): void {
  // チェーン高さを定期報告（30秒ごと）
  setInterval(() => {
    sendToSeed({ type: 'height', data: { height: chain.length, difficulty: currentDifficulty } });
  }, 30000);

  // 状態保存（60秒ごと）
  setInterval(() => {
    saveState();
  }, 60000);

  // ログ（60秒ごと）
  setInterval(() => {
    log('Stats', `チェーン: ${chain.length}ブロック, アカウント: ${accounts.size}, pending: ${pendingTxs.length}, 発行済: ${totalMined.toLocaleString()} BTR`);
  }, 60000);

  // 同期チェック（2分ごと）: 自分が遅れてたら再同期を要求
  setInterval(() => {
    if (!isSyncing) {
      sendToSeed({ type: 'check_sync', data: { height: chain.length } });
    }
  }, 120000);
}

// ============================================================
// エントリーポイント
// ============================================================

function main(): void {
  console.log('========================================');
  console.log('  BTR (Buturi Coin) Full Node');
  console.log('========================================');

  // 状態読み込み
  loadState();

  // シードノードに接続
  connectToSeed();

  // 定期処理開始
  startPeriodicTasks();

  log('Init', 'フルノード起動完了');
  log('Init', `チェーン高さ: ${chain.length}, 難易度: ${currentDifficulty}`);
}

main();