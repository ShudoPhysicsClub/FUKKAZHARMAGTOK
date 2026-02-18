// ============================================================
// BTR (Buturi Coin) - フルノード v3.0
// LWMA難易度調整 / ストリーミング同期 / pending考慮nonce&残高
// ランチャーからforkされて動く
// 全金額は Wei文字列 (1 BTR = 10^18 wei)
// ============================================================

import { connect, Socket } from 'net';
import { createHash, randomBytes } from 'crypto';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import * as fs from 'fs';
type ExtPoint = [bigint, bigint, bigint, bigint];
type AffinePoint = [bigint, bigint];

class Ed25519 {
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
    Ed25519.Gx, Ed25519.Gy, 1n, (Ed25519.Gx * Ed25519.Gy) % Ed25519.p,
  ];

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

  private static mod(n: bigint, m: bigint): bigint {
    const r = n % m; return r < 0n ? r + m : r;
  }
  private static modInv(a: bigint, m: bigint): bigint {
    let r0 = m, r1 = a < 0n ? ((a % m) + m) % m : a % m;
    let x0 = 0n, x1 = 1n;
    while (r1 !== 0n) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [x0, x1] = [x1, x0 - q * x1];
    }
    return x0 < 0n ? x0 + m : x0;
  }
  private static modPow(base: bigint, exp: bigint, m: bigint): bigint {
    let result = 1n; base = ((base % m) + m) % m;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % m;
      base = (base * base) % m; exp >>= 1n;
    }
    return result;
  }

  private static extAdd(p1: ExtPoint, p2: ExtPoint): ExtPoint {
    const P = this.p;
    const [X1, Y1, Z1, T1] = p1; const [X2, Y2, Z2, T2] = p2;
    const A = this.mod(X1 * X2, P); const B = this.mod(Y1 * Y2, P);
    const C = this.mod(this.mod(this.d * T1, P) * T2, P);
    const D = this.mod(Z1 * Z2, P);
    const E = this.mod(this.mod((X1 + Y1) * (X2 + Y2), P) - A - B, P);
    const F = this.mod(D - C, P); const G = this.mod(D + C, P); const H = this.mod(B + A, P);
    return [this.mod(E * F, P), this.mod(G * H, P), this.mod(F * G, P), this.mod(E * H, P)];
  }
  private static extDouble(pt: ExtPoint): ExtPoint {
    const P = this.p; const [X1, Y1, Z1] = pt;
    const A = this.mod(X1 * X1, P); const B = this.mod(Y1 * Y1, P);
    const C = this.mod(2n * ((Z1 * Z1) % P), P);
    const D = this.mod(P - A, P);
    const xpy = this.mod(X1 + Y1, P);
    const E = this.mod(xpy * xpy - A - B, P);
    const G = this.mod(D + B, P); const F = this.mod(G - C, P); const H = this.mod(D - B, P);
    return [this.mod(E * F, P), this.mod(G * H, P), this.mod(F * G, P), this.mod(E * H, P)];
  }
  private static extToAffine(pt: ExtPoint): AffinePoint {
    const [X, Y, Z] = pt;
    if (Z === 0n) return [0n, 1n];
    const zi = this.modInv(Z, this.p);
    return [this.mod(X * zi, this.p), this.mod(Y * zi, this.p)];
  }

  private static scalarMultG(k: bigint): ExtPoint {
    const table = this.gTable; const mask = BigInt((1 << this.W) - 1); const steps = 64;
    let R: ExtPoint = [0n, 1n, 1n, 0n];
    for (let i = steps - 1; i >= 0; i--) {
      for (let j = 0; j < this.W; j++) R = this.extDouble(R);
      const idx = Number((k >> BigInt(i * this.W)) & mask);
      if (idx !== 0) R = this.extAdd(R, table[idx]);
    }
    return R;
  }
  private static shamirMult(s: bigint, k: bigint, A: ExtPoint): ExtPoint {
    const GA = this.extAdd(this.G_EXT, A);
    let R: ExtPoint = [0n, 1n, 1n, 0n];
    for (let i = 255; i >= 0; i--) {
      R = this.extDouble(R);
      const sb = (s >> BigInt(i)) & 1n; const kb = (k >> BigInt(i)) & 1n;
      if (sb && kb) R = this.extAdd(R, GA);
      else if (sb) R = this.extAdd(R, this.G_EXT);
      else if (kb) R = this.extAdd(R, A);
    }
    return R;
  }

  private static pointToBytes(point: AffinePoint): Uint8Array {
    const [x, y] = point; const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = Number((y >> BigInt(i * 8)) & 0xffn);
    if (x & 1n) out[31] |= 0x80; return out;
  }
  private static bytesToPoint(bytes: Uint8Array): ExtPoint {
    if (bytes.length !== 32) throw new Error("Invalid point encoding");
    let y = 0n;
    for (let i = 0; i < 32; i++) y |= BigInt(bytes[i] & (i === 31 ? 0x7f : 0xff)) << BigInt(i * 8);
    if (y >= this.p) throw new Error("y coordinate out of range");
    const x_sign = (bytes[31] & 0x80) !== 0;
    const P = this.p; const y2 = (y * y) % P;
    const num = this.mod(y2 - 1n, P); const den = this.mod(this.d * y2 + 1n, P);
    const x2 = (num * this.modInv(den, P)) % P;
    if (x2 === 0n) { if (x_sign) throw new Error("Invalid point encoding"); return [0n, y, 1n, 0n]; }
    let x = this.modPow(x2, (P + 3n) / 8n, P);
    if ((x * x) % P !== this.mod(x2, P)) { x = (x * this.SQRT_M1) % P; if ((x * x) % P !== this.mod(x2, P)) throw new Error("Invalid point: no square root"); }
    if ((x & 1n) !== (x_sign ? 1n : 0n)) x = P - x;
    const xc = (x * x) % P; const yc = (y * y) % P;
    if (this.mod(yc - xc, P) !== this.mod(1n + ((this.d * ((xc * yc) % P)) % P), P)) throw new Error("Point is not on curve");
    return [x, y, 1n, (x * y) % P];
  }
  private static bigIntToBytes(n: bigint, len: number): Uint8Array {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = Number((n >> BigInt(i * 8)) & 0xffn);
    return out;
  }
  private static bytesToBigInt(bytes: Uint8Array): bigint {
    let r = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(bytes[i]);
    return r;
  }

  private static async sha512(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest("SHA-512", data.buffer as ArrayBuffer));
  }
  private static concat(...arrays: Uint8Array[]): Uint8Array {
    let len = 0; for (const a of arrays) len += a.length;
    const out = new Uint8Array(len); let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
  }
  private static clamp(s: bigint): bigint {
    return (s & ((1n << 255n) - 1n) & ~7n) | (1n << 254n);
  }

  static async getPublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length !== 32) throw new Error("Private key must be 32 bytes");
    const h = await this.sha512(privateKey);
    const s = this.clamp(this.bytesToBigInt(h.subarray(0, 32)));
    return this.pointToBytes(this.extToAffine(this.scalarMultG(s)));
  }
  static async sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length !== 32) throw new Error("Private key must be 32 bytes");
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
  static async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    if (signature.length !== 64 || publicKey.length !== 32) return false;
    try {
      const RBytes = signature.subarray(0, 32);
      const S = this.bytesToBigInt(signature.subarray(32, 64));
      if (S >= this.L) return false;
      const R = this.bytesToPoint(RBytes); const A = this.bytesToPoint(publicKey);
      const kHash = await this.sha512(this.concat(RBytes, publicKey, message));
      const k = this.mod(this.bytesToBigInt(kHash), this.L);
      const result = this.shamirMult(S, this.mod(this.L - k, this.L), A);
      const [rx, ry] = this.extToAffine(result); const [r0x, r0y] = this.extToAffine(R);
      return rx === r0x && ry === r0y;
    } catch { return false; }
  }
}

// ============================================================
// 定数 & Wei変換
// ============================================================

const DELIMITER: string = '\nLINE_BREAK\n';
const BTR_ADDRESS: string = '0x0000000000000000';
const WEI_PER_BTR = 1_000_000_000_000_000_000n; // 10^18

const CONFIG = {
  SEED_PORT: 5000,
  CHAIN_FILE: './chain.json',
  ACCOUNTS_FILE: './accounts.json',
  TOKENS_FILE: './tokens.json',

  // ジェネシス設定
  TOTAL_SUPPLY: (5_000_000_000n * WEI_PER_BTR).toString(),  // 5B BTR in Wei
  BLOCK_TIME: 180,
  BLOCK_REWARD_MIN: (20n * WEI_PER_BTR).toString(),   // 20 BTR
  BLOCK_REWARD_MAX: (70n * WEI_PER_BTR).toString(),   // 70 BTR
  GAS_FEE: (1n * WEI_PER_BTR).toString(),             // 1 BTR
  TOKEN_CREATION_FEE: (500n * WEI_PER_BTR).toString(), // 500 BTR
  TOKEN_RENAME_FEE: (500n * WEI_PER_BTR).toString(),  // 500 BTR
  TIMESTAMP_TOLERANCE: 10 * 60 * 1000,
  MAX_BLOCK_SIZE: 3 * 1024 * 1024,

  // === LWMA難易度調整 (ビット単位) ===
  DIFFICULTY_WINDOW: 20,          // 過去20ブロックで調整
  INITIAL_DIFFICULTY: 24,         // 初期難易度 (先頭24ビットが0)
  MIN_DIFFICULTY: 20,             // 最低難易度 (先頭20ビットが0)
  LWMA_CLAMP_MIN: 30,            // 外れ値フィルタ下限 (秒)
  LWMA_CLAMP_MAX: 900,           // 外れ値フィルタ上限 (15分)
  LWMA_DAMPING: 3,               // ダンピング係数 (変化量を1/3に)
  DIFFICULTY_ADJUST_START: 20,   // 調整開始ブロック高さ

  // === 同期・セキュリティ ===
  SYNC_VERIFY_TAIL: 10,         // 同期時末尾10ブロックのみ検証
  MAX_REORG_DEPTH: 10,          // 最大巻き戻し深さ
};

// ============================================================
// Wei演算ヘルパー
// ============================================================

function addWei(a: string, b: string): string {
  return (BigInt(a || "0") + BigInt(b || "0")).toString();
}

function subWei(a: string, b: string): string {
  const result = BigInt(a || "0") - BigInt(b || "0");
  if (result < 0n) {
    log('Wei', `⚠ 残高不足: ${a} - ${b} = 負数`);
    return "0";  // 負数にならないようガード
  }
  return result.toString();
}

function compareWei(a: string, b: string): number {
  const diff = BigInt(a || "0") - BigInt(b || "0");
  if (diff > 0n) return 1;
  if (diff < 0n) return -1;
  return 0;
}

function mulWei(a: string, b: string): string {
  return (BigInt(a || "0") * BigInt(b || "0")).toString();
}

function divWei(a: string, b: string): string {
  if (BigInt(b || "0") === 0n) return "0";
  return (BigInt(a || "0") / BigInt(b || "0")).toString();
}

function btrToWei(btr: number): string {
  return (BigInt(Math.floor(btr)) * WEI_PER_BTR).toString();
}

function weiToBtrDisplay(wei: string): string {
  try {
    const w = BigInt(wei);
    const whole = w / WEI_PER_BTR;
    const frac = w % WEI_PER_BTR;
    const fracStr = frac.toString().padStart(18, '0').replace(/0+$/, '');
    return fracStr ? `${whole}.${fracStr}` : whole.toString();
  } catch { return "0"; }
}

// ============================================================
// 型定義 (BigInt版)
// ============================================================

interface Transaction {
  type: 'transfer' | 'create_token' | 'token_transfer' | 'swap' | 'rename_token';
  token: string;
  from: string;
  publicKey: string;
  to?: string;
  amount?: string;      // Wei文字列
  fee: string;           // Wei文字列
  nonce: number;
  timestamp: number;
  signature: string;
  data?: TransactionData;
}

interface TransactionData {
  name?: string;
  symbol?: string;
  totalSupply?: string;   // Wei文字列
  poolRatio?: number;
  distribution?: 'creator' | 'mining' | 'split' | 'airdrop';
  tokenIn?: string;
  tokenOut?: string;
  amountIn?: string;      // Wei文字列
  minAmountOut?: string;  // Wei文字列
  newName?: string;
}

interface Block {
  height: number;
  previousHash: string;
  timestamp: number;
  nonce: number;
  difficulty: number;
  miner: string;
  reward: string;         // Wei文字列
  transactions: Transaction[];
  hash: string;
}

interface GenesisBlock extends Block {
  config: typeof CONFIG;
  message: string;
}

interface Account {
  address: string;
  balance: string;        // Wei文字列
  nonce: number;
  tokens: Record<string, string>;  // Wei文字列
}

interface TokenInfo {
  address: string;
  symbol: string;
  name: string;
  creator: string;
  createdAt: number;
  totalSupply: string;    // Wei文字列
  distributed: string;    // Wei文字列
  poolRatio: number;
  distribution: 'creator' | 'mining' | 'split' | 'airdrop';
}

interface AMMPool {
  tokenAddress: string;
  btrReserve: string;     // Wei文字列
  tokenReserve: string;   // Wei文字列
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
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`不正なhex: ${(hex || '').slice(0, 20)}`);
  }
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

// ビット難易度: ハッシュの先頭Nビットが0であるかチェック
function meetsTargetDifficulty(hash: string, difficulty: number): boolean {
  // 完全ニブル数 (4ビット単位)
  const fullNibbles = Math.floor(difficulty / 4);
  const remainBits = difficulty % 4;

  // まず完全ニブル分が全部'0'か
  for (let i = 0; i < fullNibbles; i++) {
    if (hash[i] !== '0') return false;
  }

  // 残りビットがあれば、次のニブルの上位ビットをチェック
  if (remainBits > 0 && fullNibbles < hash.length) {
    const nibbleValue = parseInt(hash[fullNibbles], 16);
    // remainBits=1 → 値は0~7 (0xxx), remainBits=2 → 0~3 (00xx), remainBits=3 → 0~1 (000x)
    const maxValue = (1 << (4 - remainBits)) - 1;
    if (nibbleValue > maxValue) return false;
  }

  return true;
}

// ============================================================
// 状態管理
// ============================================================

const chain: Block[] = [];
const accounts: Map<string, Account> = new Map();
const tokens: Map<string, TokenInfo> = new Map();
const ammPools: Map<string, AMMPool> = new Map();
const pendingTxs: Transaction[] = [];
const MAX_PENDING_TXS = 1000;  // mempool上限
let lastBlockHash: string = '';   // 最新ブロックハッシュ（報酬・レート計算用）
let totalMined: string = "0";  // Wei文字列
let currentDifficulty: number = CONFIG.INITIAL_DIFFICULTY;

// ============================================================
// アカウント管理
// ============================================================

function getAccount(address: string): Account {
  if (!accounts.has(address)) {
    accounts.set(address, {
      address,
      balance: "0",
      nonce: 0,
      tokens: {},
    });
  }
  return accounts.get(address)!;
}

// 照会専用（存在しなければデフォルト値を返すがMapには追加しない）
function peekAccount(address: string): Account {
  return accounts.get(address) || { address, balance: "0", nonce: 0, tokens: {} };
}

function getTokenBalance(address: string, tokenAddress: string): string {
  const account: Account = getAccount(address);
  return account.tokens[tokenAddress] || "0";
}

// ============================================================
// ジェネシスブロック
// ============================================================

function createGenesisBlock(): GenesisBlock {
  // タイムスタンプ固定: 全ノードで同一のジェネシスハッシュを保証
  const GENESIS_TIMESTAMP = 1739700000000; // 2025-02-16T00:00:00Z 固定
  const block: GenesisBlock = {
    height: 0,
    previousHash: '0x' + '0'.repeat(64),
    timestamp: GENESIS_TIMESTAMP,
    nonce: 0,
    difficulty: CONFIG.INITIAL_DIFFICULTY,
    miner: '0x' + '0'.repeat(40),
    reward: "0",
    transactions: [],
    hash: '',
    config: CONFIG,
    message: 'Foooooooooooooooooooo物理班最高!YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA BigInt+LWMA Edition v2.1.0',
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
    if (!valid) return { valid: false, error: `署名が無効 (from=${tx.from.slice(0, 10)}..., pubkey=${tx.publicKey.slice(0, 16)}..., sig=${signature.slice(0, 16)}...)` };
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    return { valid: false, error: `署名検証エラー: ${detail} (pubkey=${tx.publicKey.slice(0, 16)}..., sig長=${signature.length})` };
  }

  // 3. タイムスタンプ
  if (Math.abs(Date.now() - tx.timestamp) > CONFIG.TIMESTAMP_TOLERANCE) {
    return { valid: false, error: 'タイムスタンプが範囲外' };
  }

  // 4. nonce (pending考慮)
  const account: Account = getAccount(tx.from);
  // pending内のこのアドレスのnonceを集めて、次に期待されるnonceを計算
  const pendingForAddr = pendingTxs.filter(p => p.from === tx.from).map(p => p.nonce);
  let expectedNonce = account.nonce;
  if (pendingForAddr.length > 0) {
    // pending内のnonceがaccount.nonceから連続しているぶんだけカウント
    const nonceSet = new Set(pendingForAddr);
    while (nonceSet.has(expectedNonce)) {
      expectedNonce++;
    }
  }
  if (tx.nonce !== expectedNonce) {
    return { valid: false, error: `nonce不一致 (期待: ${expectedNonce}, 受信: ${tx.nonce}, 確定: ${account.nonce}, pending: ${pendingForAddr.length}件)` };
  }

  // 5. 手数料 (Wei文字列で比較)
  if (tx.fee !== CONFIG.GAS_FEE) {
    return { valid: false, error: 'ガス代が不正' };
  }

  // 6. pending考慮の実効残高を計算
  // pending内のこのアドレスのTXが消費するBTRを合算
  let pendingBtrSpent = "0";
  let pendingTokenSpent: Record<string, string> = {};
  const pendingTxsForAddr = pendingTxs.filter(p => p.from === tx.from);
  for (const ptx of pendingTxsForAddr) {
    // ガス代
    pendingBtrSpent = addWei(pendingBtrSpent, ptx.fee);
    // 送金額
    if (ptx.type === 'transfer' && ptx.token === BTR_ADDRESS && ptx.amount) {
      pendingBtrSpent = addWei(pendingBtrSpent, ptx.amount);
    }
    if (ptx.type === 'create_token') {
      pendingBtrSpent = addWei(pendingBtrSpent, CONFIG.TOKEN_CREATION_FEE);
    }
    if (ptx.type === 'rename_token') {
      pendingBtrSpent = addWei(pendingBtrSpent, CONFIG.TOKEN_RENAME_FEE);
    }
    if (ptx.type === 'swap' && ptx.data?.tokenIn === BTR_ADDRESS && ptx.data?.amountIn) {
      pendingBtrSpent = addWei(pendingBtrSpent, ptx.data.amountIn);
    }
    // トークン消費
    if (ptx.type === 'token_transfer' && ptx.amount) {
      pendingTokenSpent[ptx.token] = addWei(pendingTokenSpent[ptx.token] || "0", ptx.amount);
    }
    if (ptx.type === 'swap' && ptx.data?.tokenIn && ptx.data.tokenIn !== BTR_ADDRESS && ptx.data?.amountIn) {
      pendingTokenSpent[ptx.data.tokenIn] = addWei(pendingTokenSpent[ptx.data.tokenIn] || "0", ptx.data.amountIn);
    }
  }

  const effectiveBalance = subWei(account.balance, pendingBtrSpent);

  // ガス代分チェック
  if (compareWei(effectiveBalance, tx.fee) < 0) {
    return { valid: false, error: `ガス代の残高不足 (実効残高=${effectiveBalance.slice(0, 20)}, pending消費=${pendingBtrSpent.slice(0, 20)})` };
  }

  // 7. type別チェック
  switch (tx.type) {
    case 'transfer': {
      if (!tx.to || !tx.amount || compareWei(tx.amount, "0") <= 0) {
        return { valid: false, error: 'transfer: 宛先または金額が不正' };
      }
      if (tx.token === BTR_ADDRESS) {
        if (compareWei(effectiveBalance, addWei(tx.amount, tx.fee)) < 0) {
          return { valid: false, error: `BTR残高不足 (実効=${effectiveBalance.slice(0, 20)})` };
        }
      }
      break;
    }
    case 'token_transfer': {
      if (!tx.to || !tx.amount || compareWei(tx.amount, "0") <= 0) {
        return { valid: false, error: 'token_transfer: 宛先または金額が不正' };
      }
      const tokenBal: string = getTokenBalance(tx.from, tx.token);
      const effectiveTokenBal = subWei(tokenBal, pendingTokenSpent[tx.token] || "0");
      if (compareWei(effectiveTokenBal, tx.amount) < 0) {
        return { valid: false, error: 'トークン残高不足 (pending考慮)' };
      }
      break;
    }
    case 'create_token': {
      if (!tx.data?.name || !tx.data?.symbol || !tx.data?.totalSupply || compareWei(tx.data.totalSupply, "0") <= 0) {
        return { valid: false, error: 'create_token: データが不正' };
      }
      if (compareWei(effectiveBalance, addWei(CONFIG.TOKEN_CREATION_FEE, tx.fee)) < 0) {
        return { valid: false, error: 'トークン作成費の残高不足 (pending考慮)' };
      }
      // tokenAddress衝突チェック
      const predictedAddr = '0x' + sha256(tx.signature + tx.timestamp).slice(0, 40);
      if (tokens.has(predictedAddr)) {
        return { valid: false, error: 'tokenAddress衝突' };
      }
      // poolRatio範囲チェック
      const poolRatio = tx.data.poolRatio || 0;
      if (poolRatio < 0 || poolRatio > 1) {
        return { valid: false, error: 'poolRatio範囲外 (0~1)' };
      }
      break;
    }
    case 'swap': {
      if (!tx.data?.tokenIn || !tx.data?.tokenOut || !tx.data?.amountIn || compareWei(tx.data.amountIn, "0") <= 0) {
        return { valid: false, error: 'swap: データが不正' };
      }
      if (tx.data.tokenIn === tx.data.tokenOut) {
        return { valid: false, error: 'swap: 同一トークン間のスワップ不可' };
      }
      if (tx.data.tokenIn === BTR_ADDRESS) {
        if (compareWei(effectiveBalance, addWei(tx.data.amountIn, tx.fee)) < 0) {
          return { valid: false, error: 'swap: BTR残高不足 (pending考慮)' };
        }
      } else {
        const tokenBal: string = getTokenBalance(tx.from, tx.data.tokenIn);
        const effectiveTokenBal = subWei(tokenBal, pendingTokenSpent[tx.data.tokenIn] || "0");
        if (compareWei(effectiveTokenBal, tx.data.amountIn) < 0) {
          return { valid: false, error: 'swap: トークン残高不足 (pending考慮)' };
        }
      }
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
      if (compareWei(effectiveBalance, addWei(CONFIG.TOKEN_RENAME_FEE, tx.fee)) < 0) {
        return { valid: false, error: 'トークン名変更費の残高不足 (pending考慮)' };
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

  // ガス代
  if (!isSelfMining) {
    sender.balance = subWei(sender.balance, tx.fee);
    miner.balance = addWei(miner.balance, tx.fee);
  }
  sender.nonce++;

  switch (tx.type) {
    case 'transfer': {
      const receiver: Account = getAccount(tx.to!);
      if (tx.token === BTR_ADDRESS) {
        sender.balance = subWei(sender.balance, tx.amount!);
        receiver.balance = addWei(receiver.balance, tx.amount!);
      }
      break;
    }
    case 'token_transfer': {
      const receiver: Account = getAccount(tx.to!);
      const senderBal: string = sender.tokens[tx.token] || "0";
      sender.tokens[tx.token] = subWei(senderBal, tx.amount!);
      const receiverBal: string = receiver.tokens[tx.token] || "0";
      receiver.tokens[tx.token] = addWei(receiverBal, tx.amount!);
      break;
    }
    case 'create_token': {
      sender.balance = subWei(sender.balance, CONFIG.TOKEN_CREATION_FEE);
      if (!isSelfMining) {
        miner.balance = addWei(miner.balance, CONFIG.TOKEN_CREATION_FEE);
      }

      const tokenAddress: string = '0x' + sha256(tx.signature + tx.timestamp).slice(0, 40);
      const poolRatio: number = tx.data!.poolRatio || 0;
      const totalSupply: string = tx.data!.totalSupply!;

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

      // 配布: BigIntで計算
      const totalBig = BigInt(totalSupply);
      // poolRatioは0~1のfloat — 整数化して計算: poolAmount = total * (poolRatio * 10000) / 10000
      const poolRatioInt = BigInt(Math.floor(poolRatio * 10000));
      const poolAmount = (totalBig * poolRatioInt) / 10000n;
      const creatorAmount = totalBig - poolAmount;

      if (creatorAmount > 0n) {
        sender.tokens[tokenAddress] = addWei(sender.tokens[tokenAddress] || "0", creatorAmount.toString());
      }

      // AMM プール作成
      if (poolAmount > 0n) {
        ammPools.set(tokenAddress, {
          tokenAddress,
          btrReserve: CONFIG.TOKEN_CREATION_FEE,  // 作成費がプールの初期BTRリザーブ
          tokenReserve: poolAmount.toString(),
        });
      }
      break;
    }
    case 'swap': {
      executeSwap(tx);
      break;
    }
    case 'rename_token': {
      sender.balance = subWei(sender.balance, CONFIG.TOKEN_RENAME_FEE);
      if (!isSelfMining) {
        miner.balance = addWei(miner.balance, CONFIG.TOKEN_RENAME_FEE);
      }
      const token: TokenInfo | undefined = tokens.get(tx.token);
      if (token) {
        token.name = tx.data!.newName!;
      }
      break;
    }
  }
}

// ============================================================
// AMM (BigInt版)
// ============================================================

function getAMMRate(tokenAddress: string): string {
  const pool: AMMPool | undefined = ammPools.get(tokenAddress);
  if (!pool || compareWei(pool.tokenReserve, "0") <= 0) return "0";
  // rate = btrReserve * 97 / (tokenReserve * 100) — 3%手数料込み
  // 精度保持のため WEI_PER_BTR をかけてから割る
  const rate = (BigInt(pool.btrReserve) * 97n * WEI_PER_BTR) / (BigInt(pool.tokenReserve) * 100n);
  return rate.toString();
}

function getFluctuatedRate(tokenAddress: string, minute: number): string {
  const baseRate: string = getAMMRate(tokenAddress);
  if (baseRate === "0" || !lastBlockHash) return baseRate;

  const seed: string = sha256(lastBlockHash + tokenAddress + minute);
  const fluctuation: number = parseInt(seed.slice(0, 8), 16);
  const change: number = (fluctuation % 3000 - 1500); // -1500 ~ +1500
  // rate = base * (10000 + change) / 10000
  const base = BigInt(baseRate);
  const result = (base * BigInt(10000 + change)) / 10000n;
  return result.toString();
}

const FEE_NUMERATOR = 3n;
const FEE_DENOMINATOR = 100n;

function executeSwap(tx: Transaction): void {
  const tokenIn: string = tx.data!.tokenIn!;
  const tokenOut: string = tx.data!.tokenOut!;
  const amountIn: bigint = BigInt(tx.data!.amountIn!);
  const sender: Account = getAccount(tx.from);

  if (tokenIn === BTR_ADDRESS) {
    // BTR → Token
    const pool: AMMPool | undefined = ammPools.get(tokenOut);
    if (!pool) return;
    if (compareWei(sender.balance, amountIn.toString()) < 0) return;

    const fee = amountIn * FEE_NUMERATOR / FEE_DENOMINATOR;
    const amountInAfterFee = amountIn - fee;

    const amountOut = (amountInAfterFee * BigInt(pool.tokenReserve)) / (BigInt(pool.btrReserve) + amountInAfterFee);
    if (amountOut <= 0n) return;  // ゼロ出力防止
    if (compareWei(pool.tokenReserve, amountOut.toString()) <= 0) return;  // プール枯渇防止

    sender.balance = subWei(sender.balance, amountIn.toString());
    pool.btrReserve = addWei(pool.btrReserve, amountIn.toString());
    pool.tokenReserve = subWei(pool.tokenReserve, amountOut.toString());
    sender.tokens[tokenOut] = addWei(sender.tokens[tokenOut] || "0", amountOut.toString());

  } else if (tokenOut === BTR_ADDRESS) {
    // Token → BTR
    const pool: AMMPool | undefined = ammPools.get(tokenIn);
    if (!pool) return;
    const senderBal: string = sender.tokens[tokenIn] || "0";
    if (compareWei(senderBal, amountIn.toString()) < 0) return;

    const fee = amountIn * FEE_NUMERATOR / FEE_DENOMINATOR;
    const amountInAfterFee = amountIn - fee;

    const amountOut = (amountInAfterFee * BigInt(pool.btrReserve)) / (BigInt(pool.tokenReserve) + amountInAfterFee);
    if (amountOut <= 0n) return;
    if (compareWei(pool.btrReserve, amountOut.toString()) <= 0) return;

    sender.tokens[tokenIn] = subWei(senderBal, amountIn.toString());
    pool.tokenReserve = addWei(pool.tokenReserve, amountIn.toString());
    pool.btrReserve = subWei(pool.btrReserve, amountOut.toString());
    sender.balance = addWei(sender.balance, amountOut.toString());

  } else {
    // Token → Token (TokenA → BTR → TokenB)
    const poolA: AMMPool | undefined = ammPools.get(tokenIn);
    const poolB: AMMPool | undefined = ammPools.get(tokenOut);
    if (!poolA || !poolB) return;
    const senderBal: string = sender.tokens[tokenIn] || "0";
    if (compareWei(senderBal, amountIn.toString()) < 0) return;

    const feeA = amountIn * FEE_NUMERATOR / FEE_DENOMINATOR;
    const amountInAfterFee = amountIn - feeA;

    // TokenA → BTR
    const btrAmount = (amountInAfterFee * BigInt(poolA.btrReserve)) / (BigInt(poolA.tokenReserve) + amountInAfterFee);
    if (btrAmount <= 0n) return;
    if (compareWei(poolA.btrReserve, btrAmount.toString()) <= 0) return;

    // BTR → TokenB (2回目手数料)
    const feeB = btrAmount * FEE_NUMERATOR / FEE_DENOMINATOR;
    const btrAmountAfterFee = btrAmount - feeB;

    const amountOut = (btrAmountAfterFee * BigInt(poolB.tokenReserve)) / (BigInt(poolB.btrReserve) + btrAmountAfterFee);
    if (amountOut <= 0n) return;
    if (compareWei(poolB.tokenReserve, amountOut.toString()) <= 0) return;

    sender.tokens[tokenIn] = subWei(senderBal, amountIn.toString());
    poolA.tokenReserve = addWei(poolA.tokenReserve, amountIn.toString());
    poolA.btrReserve = subWei(poolA.btrReserve, btrAmount.toString());
    poolB.btrReserve = addWei(poolB.btrReserve, btrAmount.toString());
    poolB.tokenReserve = subWei(poolB.tokenReserve, amountOut.toString());
    sender.tokens[tokenOut] = addWei(sender.tokens[tokenOut] || "0", amountOut.toString());
  }
}

// ============================================================
// ブロック検証
// ============================================================

async function verifyBlock(block: Block): Promise<{ valid: boolean; error?: string }> {
  if (block.difficulty < 1 || !Number.isInteger(block.difficulty)) {
    return { valid: false, error: `難易度が不正: ${block.difficulty}` };
  }

  // 最低難易度チェック（20ブロック以降はMIN_DIFFICULTYを要求）
  if (chain.length >= CONFIG.DIFFICULTY_ADJUST_START && block.difficulty < CONFIG.MIN_DIFFICULTY) {
    return { valid: false, error: `最低難易度未満: ブロック=${block.difficulty}, 最低=${CONFIG.MIN_DIFFICULTY}` };
  }

  // チェーンベースで期待される難易度を計算（ブロック単位調整のみ）
  const expectedDiff = calculateDifficultyFromChain(chain);
  // ブロックの難易度は期待値以上であること（高い分にはOK）
  if (block.difficulty < expectedDiff && chain.length > 0) {
    return { valid: false, error: `難易度不足: ブロック=${block.difficulty}, 期待>=${expectedDiff} (LWMA計算)` };
  }

  const expectedHash: string = computeBlockHash(block);
  if (block.hash !== expectedHash) {
    return { valid: false, error: `ブロックハッシュ不一致 (計算=${expectedHash.slice(0, 16)}..., ブロック=${block.hash.slice(0, 16)}...)` };
  }

  if (!meetsTargetDifficulty(block.hash, block.difficulty)) {
    return { valid: false, error: `PoW条件を満たしていない (先頭${block.difficulty}ビットが0である必要)` };
  }

  if (chain.length > 0) {
    const prev: Block = chain[chain.length - 1];
    if (block.previousHash !== prev.hash) {
      return { valid: false, error: `previousHash不一致 (期待=${prev.hash.slice(0, 16)}..., 受信=${block.previousHash.slice(0, 16)}...)` };
    }
    if (block.height !== prev.height + 1) {
      return { valid: false, error: `height不一致 (期待=${prev.height + 1}, 受信=${block.height})` };
    }

    // 難易度は1ブロックで最大+1まで（急激な上昇を防止）
    if (block.difficulty > prev.difficulty + 1) {
      return { valid: false, error: `難易度の急上昇: ${prev.difficulty}→${block.difficulty} (最大+1)` };
    }
  }

  // タイムスタンプチェック
  if (block.timestamp > Date.now() + 30000) {
    return { valid: false, error: 'タイムスタンプが未来すぎる' };
  }
  // 前ブロックより古いタイムスタンプは拒否（難易度操作防止）
  if (chain.length > 0) {
    const prev: Block = chain[chain.length - 1];
    if (block.timestamp < prev.timestamp) {
      return { valid: false, error: `タイムスタンプが前ブロックより古い (${block.timestamp} < ${prev.timestamp})` };
    }
  }

  const size: number = Buffer.byteLength(JSON.stringify(block.transactions));
  if (size > CONFIG.MAX_BLOCK_SIZE) {
    return { valid: false, error: `ブロックサイズ超過 (${size} > ${CONFIG.MAX_BLOCK_SIZE})` };
  }

  // 報酬チェック (Wei文字列比較)
  if (compareWei(block.reward, CONFIG.BLOCK_REWARD_MIN) < 0 || compareWei(block.reward, CONFIG.BLOCK_REWARD_MAX) > 0) {
    return { valid: false, error: `報酬が範囲外 (${block.reward.slice(0, 20)}...)` };
  }

  // 報酬の正確な値を検証（ブロックハッシュベース）
  if (block.height > 0) {
    const expectedReward = calculateReward(block.height);
    if (block.reward !== expectedReward) {
      return { valid: false, error: `報酬不一致: ブロック=${block.reward.slice(0, 20)}, 期待=${expectedReward.slice(0, 20)}` };
    }
  }

  // ブロック内TXの重複チェック（署名重複）
  const txSigs = new Set<string>();
  for (const tx of block.transactions) {
    if (txSigs.has(tx.signature)) {
      return { valid: false, error: `ブロック内TX重複: ${tx.signature.slice(0, 16)}...` };
    }
    txSigs.add(tx.signature);
  }

  // ブロック内Nonce重複チェック（同一アドレスが同じnonceを使い回していないか）
  const txNonces = new Map<string, Set<number>>();
  for (const tx of block.transactions) {
    if (!txNonces.has(tx.from)) txNonces.set(tx.from, new Set());
    const nonces = txNonces.get(tx.from)!;
    if (nonces.has(tx.nonce)) {
      return { valid: false, error: `ブロック内Nonce重複: ${tx.from.slice(0, 10)}... nonce=${tx.nonce}` };
    }
    nonces.add(tx.nonce);
  }

  // ブロック内TXのnonce連続性チェック（アカウントのnonce順に並んでいるか）
  // 同一アドレスのTXは確定nonce, nonce+1, nonce+2... と連続していなければならない
  for (const [addr, nonces] of txNonces) {
    const sorted = Array.from(nonces).sort((a, b) => a - b);
    const account = peekAccount(addr);
    const expectedStart = account.nonce;
    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i] !== expectedStart + i) {
        return { valid: false, error: `ブロック内Nonce不連続: ${addr.slice(0, 10)}... 期待=${expectedStart + i}, 実際=${sorted[i]}` };
      }
    }
  }

  // ブロック内TXの署名検証（PoW/ハッシュ計算量に比べれば軽い）
  for (const tx of block.transactions) {
    try {
      const { signature, ...rest } = tx;
      const message: string = canonicalJSON(rest);
      const valid: boolean = await Ed25519.verify(
        hexToBytes(signature),
        new TextEncoder().encode(message),
        hexToBytes(tx.publicKey)
      );
      if (!valid) {
        return { valid: false, error: `ブロック内TX署名無効: ${tx.signature.slice(0, 16)}... from ${tx.from.slice(0, 10)}...` };
      }
    } catch (e) {
      return { valid: false, error: `ブロック内TX署名検証エラー: ${tx.signature.slice(0, 16)}...` };
    }

    // 公開鍵→アドレス整合性
    const expectedAddr = '0x' + sha256(tx.publicKey).slice(0, 40);
    if (expectedAddr !== tx.from) {
      return { valid: false, error: `ブロック内TX: 公開鍵とアドレス不一致 ${tx.from.slice(0, 10)}...` };
    }
  }

  return { valid: true };
}

// ============================================================
// ブロック適用
// ============================================================

function applyBlock(block: Block): void {
  // マイニング報酬
  if (block.height > 0 && compareWei(totalMined, CONFIG.TOTAL_SUPPLY) < 0) {
    const miner: Account = getAccount(block.miner);
    const remaining = subWei(CONFIG.TOTAL_SUPPLY, totalMined);
    const reward: string = compareWei(block.reward, remaining) <= 0 ? block.reward : remaining;
    miner.balance = addWei(miner.balance, reward);
    totalMined = addWei(totalMined, reward);
  }

  // トランザクション適用
  for (const tx of block.transactions) {
    applyTransaction(tx, block.miner);
  }

  // マイニングトークン配布
  const MINING_TOKEN_REWARD = (100n * WEI_PER_BTR).toString(); // 100トークン/ブロック
  for (const [, token] of tokens) {
    if (token.distribution === 'mining' && compareWei(token.distributed, token.totalSupply) < 0) {
      const miner: Account = getAccount(block.miner);
      const remaining = subWei(token.totalSupply, token.distributed);
      const tokenReward = compareWei(MINING_TOKEN_REWARD, remaining) <= 0 ? MINING_TOKEN_REWARD : remaining;
      miner.tokens[token.address] = addWei(miner.tokens[token.address] || "0", tokenReward);
      token.distributed = addWei(token.distributed, tokenReward);
    }
  }

  chain.push(block);
  lastBlockHash = block.hash;  // 報酬・レート計算用

  // ブロックファイル保存 (rebuilding中はスキップ、後でsaveStateがまとめて保存)
  if (!isRebuilding) {
    try {
      const filename = `./chain/${block.height.toString().padStart(64, '0')}.json`;
      writeFileSync(filename, JSON.stringify(block));
    } catch (e) {
      log('Save', `ブロック保存失敗: ${e}`);
    }
  }

  adjustDifficulty();

  // pending から適用済みTxを除去
  // 1. ブロック内TXの署名一致で除去
  const txSigs: Set<string> = new Set(block.transactions.map(tx => tx.signature));
  // 2. ブロック内TXで消費されたnonceも除去（同一アドレス+同一nonceの別TX）
  const usedNonces = new Map<string, Set<number>>();
  for (const tx of block.transactions) {
    if (!usedNonces.has(tx.from)) usedNonces.set(tx.from, new Set());
    usedNonces.get(tx.from)!.add(tx.nonce);
  }
  const remaining: Transaction[] = pendingTxs.filter(tx => {
    if (txSigs.has(tx.signature)) return false;  // 署名一致
    const nonces = usedNonces.get(tx.from);
    if (nonces && nonces.has(tx.nonce)) return false;  // 同一アドレス+nonceが消費済み
    // account.nonceより古いTXも除去
    const acc = peekAccount(tx.from);
    if (tx.nonce < acc.nonce) return false;
    return true;
  });
  pendingTxs.length = 0;
  pendingTxs.push(...remaining);
}

// ============================================================
// 難易度調整 (LWMA: 線形加重移動平均)
//   - 過去20ブロックの時間を重み付け平均（直近ほど重い）
//   - 外れ値フィルタ: 30秒~15分にクランプ
//   - ダンピング: 変化量を1/3に抑制
//   - 最低難易度: CONFIG.MIN_DIFFICULTY
//   - 調整開始: CONFIG.DIFFICULTY_ADJUST_START ブロック以降
// ============================================================

function calculateDifficultyFromChain(c: Block[]): number {
  // 20ブロック未満の場合は初期難易度
  if (c.length < CONFIG.DIFFICULTY_ADJUST_START + 1) {
    return CONFIG.INITIAL_DIFFICULTY;
  }

  // ジェネシス(height=0)を除外した範囲でwindowを計算
  const nonGenesis = c.slice(1); // height 1以降
  const window = Math.min(CONFIG.DIFFICULTY_WINDOW, nonGenesis.length - 1);
  if (window < 2) return CONFIG.INITIAL_DIFFICULTY;

  const recent = nonGenesis.slice(-window - 1); // window+1個取って間隔を出す

  // LWMA: 重み付き平均ブロック時間を計算
  let weightedSum = 0;
  let weightTotal = 0;

  for (let i = 1; i < recent.length; i++) {
    let interval = (recent[i].timestamp - recent[i - 1].timestamp) / 1000; // 秒

    // 外れ値フィルタ: クランプ
    interval = Math.max(CONFIG.LWMA_CLAMP_MIN, Math.min(CONFIG.LWMA_CLAMP_MAX, interval));

    const weight = i; // 直近ほど重い (1, 2, 3, ..., window)
    weightedSum += interval * weight;
    weightTotal += weight;
  }

  const lwmaAvg = weightedSum / weightTotal; // 加重平均ブロック時間(秒)
  const target = CONFIG.BLOCK_TIME; // 180秒

  // 理想の変動値: 正なら遅すぎ(難易度下げ)、負なら速すぎ(難易度上げ)
  const ratio = lwmaAvg / target;
  const currentDiff = c[c.length - 1].difficulty;

  let newDiff: number;
  if (ratio < 0.85) {
    // 速すぎ → 難易度UP (ダンピング適用)
    const change = Math.ceil((1 / ratio - 1) / CONFIG.LWMA_DAMPING);
    newDiff = currentDiff + Math.max(1, change);
  } else if (ratio > 1.15) {
    // 遅すぎ → 難易度DOWN (ダンピング適用)
    const change = Math.ceil((ratio - 1) / CONFIG.LWMA_DAMPING);
    newDiff = currentDiff - Math.max(1, change);
  } else {
    newDiff = currentDiff;
  }

  // 最低難易度制限
  newDiff = Math.max(CONFIG.MIN_DIFFICULTY, newDiff);

  // 1ブロックで最大+1しか上がらない（急激な上昇防止）
  newDiff = Math.min(currentDiff + 1, newDiff);

  return newDiff;
}

function adjustDifficulty(): void {
  const newDiff = calculateDifficultyFromChain(chain);
  const oldDifficulty = currentDifficulty;
  currentDifficulty = newDiff;

  // rebuildState中は通知しない（大量送信防止）
  if (isRebuilding) return;

  if (currentDifficulty !== oldDifficulty) {
    const dir = currentDifficulty > oldDifficulty ? 'UP' : 'DOWN';
    log('Difficulty', `難易度${dir}: ${currentDifficulty} (前=${oldDifficulty}, チェーン高=${chain.length})`);

    // クライアントに通知
    sendToSeed({
      type: 'difficulty_update',
      data: {
        difficulty: currentDifficulty,
        height: chain.length,
        previousHash: chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64),
        reward: calculateReward(chain.length),
      }
    });
  }
}

// ============================================================
// ブロック報酬算出
// ============================================================

// ============================================================
// ブロックテンプレート用TX選別
// pendingTxsから、nonce連続性を保ったTXだけを選出
// ============================================================

function selectValidTxsForBlock(txs: Transaction[]): Transaction[] {
  // アドレスごとにTXをグループ化
  const byAddr = new Map<string, Transaction[]>();
  for (const tx of txs) {
    if (!byAddr.has(tx.from)) byAddr.set(tx.from, []);
    byAddr.get(tx.from)!.push(tx);
  }

  const result: Transaction[] = [];

  for (const [addr, addrTxs] of byAddr) {
    const account = peekAccount(addr);
    let nextNonce = account.nonce;

    // nonce順にソート
    addrTxs.sort((a, b) => a.nonce - b.nonce);

    // 同一nonceで重複がある場合: 最初のものだけ採用
    const seen = new Set<number>();
    for (const tx of addrTxs) {
      if (seen.has(tx.nonce)) continue;  // 同じnonceの2個目以降はスキップ
      seen.add(tx.nonce);

      if (tx.nonce === nextNonce) {
        result.push(tx);
        nextNonce++;
      } else if (tx.nonce > nextNonce) {
        break;  // 飛びがあったら以降は無効
      }
      // tx.nonce < nextNonce はスキップ（既に処理済み）
    }
  }

  return result;
}

function calculateReward(height: number): string {
  if (compareWei(totalMined, CONFIG.TOTAL_SUPPLY) >= 0) return "0";

  // ブロックハッシュベース: 前ブロックのハッシュ + height で決定論的に報酬を算出
  const prevHash = chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64);
  const seed: string = sha256(prevHash + 'BTR_REWARD' + height);
  const value: number = parseInt(seed.slice(0, 8), 16);
  const range = 70 - 20 + 1;
  const rewardBtr = 20 + (value % range);
  const rewardWei = (BigInt(rewardBtr) * WEI_PER_BTR).toString();

  const remaining = subWei(CONFIG.TOTAL_SUPPLY, totalMined);
  return compareWei(rewardWei, remaining) <= 0 ? rewardWei : remaining;
}

// ============================================================
// フォーク選択
// ============================================================

function calculateChainWork(c: Block[]): bigint {
  return c.reduce((sum, b) => sum + (2n ** BigInt(b.difficulty)), 0n);
}

function selectChain(otherChain: Block[]): boolean {
  // 巻き戻し深さ制限: 共通祖先からの差分がMAX_REORG_DEPTHを超えたら拒否
  if (chain.length > 0 && otherChain.length > 0) {
    // 共通祖先を探す
    let commonHeight = -1;
    const minLen = Math.min(chain.length, otherChain.length);
    for (let i = minLen - 1; i >= 0; i--) {
      if (chain[i] && otherChain[i] && chain[i].hash === otherChain[i].hash) {
        commonHeight = i;
        break;
      }
    }
    const reorgDepth = chain.length - 1 - commonHeight;
    if (reorgDepth > CONFIG.MAX_REORG_DEPTH) {
      log('Chain', `⚠ リオーグ拒否: 深さ${reorgDepth} > 上限${CONFIG.MAX_REORG_DEPTH}`);
      return false;
    }
  }

  const myWork = calculateChainWork(chain);
  const otherWork = calculateChainWork(otherChain);

  if (otherWork > myWork) {
    log('Chain', `フォーク解決(ワーク量): 現在=${myWork}, 受信=${otherWork} (長さ: ${chain.length} vs ${otherChain.length})`);
    rebuildState(otherChain);
    return true;
  }

  if (otherWork === myWork && otherChain.length > chain.length) {
    log('Chain', `フォーク解決(同ワーク/長さ優先): ${chain.length} → ${otherChain.length}`);
    rebuildState(otherChain);
    return true;
  }

  return false;
}

let isRebuilding: boolean = false;

function rebuildState(newChain: Block[]): void {
  // 末尾 SYNC_VERIFY_TAIL ブロックのPoW/ハッシュチェーン検証
  const tailStart = Math.max(0, newChain.length - CONFIG.SYNC_VERIFY_TAIL);
  for (let i = tailStart; i < newChain.length; i++) {
    const block = newChain[i];

    // ✅ genesisブロックは検証スキップ
    const isGenesis = block.height === 0 &&
      block.previousHash === "0x0000000000000000000000000000000000000000000000000000000000000000";

    if (!isGenesis) {
      // ハッシュ整合性
      const expected = computeBlockHash(block);
      if (block.hash !== expected) {
        log('Chain', `⚠ rebuild拒否: ブロック#${block.height}のハッシュ不正`);
        return;
      }
      // PoW
      if (!meetsTargetDifficulty(block.hash, block.difficulty)) {
        log('Chain', `⚠ rebuild拒否: ブロック#${block.height}のPoW不正`);
        return;
      }
    }

    // ハッシュチェーン連結
    if (i > 0 && block.previousHash !== newChain[i - 1].hash) {
      log('Chain', `⚠ rebuild拒否: ブロック#${block.height}のpreviousHash不一致`);
      return;
    }
  }

  chain.length = 0;
  accounts.clear();
  tokens.clear();
  ammPools.clear();
  totalMined = "0";
  currentDifficulty = CONFIG.INITIAL_DIFFICULTY;
  lastBlockHash = '';

  isRebuilding = true;
  for (const block of newChain) {
    applyBlock(block);
  }
  isRebuilding = false;

  log('Chain', `rebuild完了: ${newChain.length}ブロック (末尾${CONFIG.SYNC_VERIFY_TAIL}検証済み)`);
}

// ============================================================
// 永続化
// ============================================================

function saveState(): void {
  try {
    if (!existsSync('./chain')) fs.mkdirSync('./chain', { recursive: true });
    if (!existsSync('./users')) fs.mkdirSync('./users', { recursive: true });
    if (!existsSync('./tokens')) fs.mkdirSync('./tokens', { recursive: true });

    for (const block of chain) {
      const filename = `./chain/${block.height.toString().padStart(64, '0')}.json`;
      writeFileSync(filename, JSON.stringify(block));
    }

    for (const [address, account] of accounts) {
      const filename = `./users/${address}.json`;
      writeFileSync(filename, JSON.stringify(account));
    }

    for (const [address, token] of tokens) {
      const filename = `./tokens/${address}.json`;
      writeFileSync(filename, JSON.stringify(token));
    }

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
    if (!existsSync('./chain')) fs.mkdirSync('./chain', { recursive: true });
    if (!existsSync('./users')) fs.mkdirSync('./users', { recursive: true });
    if (!existsSync('./tokens')) fs.mkdirSync('./tokens', { recursive: true });

    let chainLength = 0;
    if (existsSync('./state_meta.json')) {
      const meta = JSON.parse(readFileSync('./state_meta.json', 'utf-8'));
      chainLength = meta.chainLength || 0;
    }

    if (chainLength > 0) {
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
        log('Load', `チェーン読み込み: ${chain.length}ブロック`);
      } else {
        const genesis: GenesisBlock = createGenesisBlock();
        chain.push(genesis);
        lastBlockHash = genesis.hash;
        log('Load', 'ジェネシスブロック作成');
      }
    } else {
      if (existsSync(CONFIG.CHAIN_FILE)) {
        log('Load', '旧形式検出: 移行不可（BigInt版は互換性なし）');
      }
      const genesis: GenesisBlock = createGenesisBlock();
      chain.push(genesis);
      lastBlockHash = genesis.hash;
      log('Load', 'ジェネシスブロック作成 (BigInt版)');
    }
  } catch (e: unknown) {
    const msg: string = e instanceof Error ? e.message : String(e);
    log('Load', `読み込み失敗: ${msg}`);
    const genesis: GenesisBlock = createGenesisBlock();
    chain.push(genesis);
    lastBlockHash = genesis.hash;
  }
}

// ============================================================
// チェーン同期
// ============================================================

// ============================================================
// 同期管理（ストリーミング: チャンクごとに即ディスク書き出し、上限なし）
// ============================================================

const SYNC_DIR = './sync_chain';
let syncReceivedBlocks = 0;
let syncExpectedHeight = 0;
let syncLastHash = '';
let syncExpectedFrom: number = 0;
let syncTimer: ReturnType<typeof setTimeout> | null = null;
let isSyncing: boolean = false;

function cleanSyncDir(): void {
  try {
    if (existsSync(SYNC_DIR)) {
      for (const f of fs.readdirSync(SYNC_DIR)) fs.unlinkSync(`${SYNC_DIR}/${f}`);
    } else {
      fs.mkdirSync(SYNC_DIR, { recursive: true });
    }
  } catch (e) { log('Sync', `sync_chain クリア失敗: ${e}`); }
}

function writeSyncBlocks(blocks: Block[]): void {
  if (!existsSync(SYNC_DIR)) fs.mkdirSync(SYNC_DIR, { recursive: true });
  for (const block of blocks) {
    const filename = `${SYNC_DIR}/${block.height.toString().padStart(10, '0')}.json`;
    writeFileSync(filename, JSON.stringify(block));
  }
}

function startSyncTimeout(): void {
  if (syncTimer) clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    if (isSyncing) {
      log('Sync', 'タイムアウト — フォールバック');
      isSyncing = false;
      syncReceivedBlocks = 0;
      cleanSyncDir();
      sendToSeed({ type: 'request_chain', data: { fromHeight: chain.length } });
      syncTimer = setTimeout(() => {
        if (chain.length <= 1) log('Sync', '同期失敗、ジェネシスから開始');
        syncTimer = null;
      }, 15000);
    }
  }, 15000);
}

function finishSync(): void {
  isSyncing = false;
  if (syncTimer) { clearTimeout(syncTimer); syncTimer = null; }

  currentDifficulty = calculateDifficultyFromChain(chain);
  log('Sync', `難易度をチェーンから再計算: diff=${currentDifficulty}`);

  saveState();
  try {
    const meta = { chainLength: chain.length, accountCount: accounts.size, tokenCount: tokens.size, lastSaved: Date.now() };
    writeFileSync('./state_meta.json', JSON.stringify(meta, null, 2));
  } catch (e) { log('Save', `メタデータ保存失敗: ${e}`); }
  sendToSeed({ type: 'height', data: { height: chain.length, difficulty: currentDifficulty } });
  log('Sync', `同期完了: ${chain.length}ブロック, 難易度=${currentDifficulty}`);
}

// sync_chain/ のブロックを既存チェーンとマージして適用
function applySyncedChain(): void {
  const files = fs.readdirSync(SYNC_DIR).sort();
  if (files.length === 0) { cleanSyncDir(); finishSync(); return; }

  // 受信ブロックの先頭と末尾を読む
  const firstBlock: Block = JSON.parse(readFileSync(`${SYNC_DIR}/${files[0]}`, 'utf-8'));
  const lastBlock: Block = JSON.parse(readFileSync(`${SYNC_DIR}/${files[files.length - 1]}`, 'utf-8'));
  const syncStartHeight = firstBlock.height;
  const syncEndHeight = lastBlock.height;

  log('Sync', `受信ブロック: #${syncStartHeight}〜#${syncEndHeight} (${files.length}件), 現在のチェーン: ${chain.length}ブロック`);

  // 受信チェーンの末尾が現在のチェーンより高くなければスキップ
  if (syncEndHeight + 1 <= chain.length) {
    log('Sync', `受信末尾 #${syncEndHeight} ≤ 現在 #${chain.length - 1} → スキップ`);
    cleanSyncDir();
    finishSync();
    return;
  }

  // 差分同期: syncStartHeight > 0 かつ既存チェーンと繋がる場合
  if (syncStartHeight > 0 && syncStartHeight <= chain.length) {
    log('Sync', `差分マージ: 既存#0〜#${syncStartHeight - 1} + 受信#${syncStartHeight}〜#${syncEndHeight}`);

    // ハッシュチェーン連結検証
    if (chain[syncStartHeight - 1] && firstBlock.previousHash !== chain[syncStartHeight - 1].hash) {
      log('Sync', `⚠ チェーン連結不一致 → フォーク検出、スキップ`);
      cleanSyncDir(); finishSync(); return;
    }

    // 受信ブロックの末尾を検証
    const verifyCount = Math.min(files.length, CONFIG.SYNC_VERIFY_TAIL);
    const verifyStart = files.length - verifyCount;
    for (let i = verifyStart; i < files.length; i++) {
      const block: Block = JSON.parse(readFileSync(`${SYNC_DIR}/${files[i]}`, 'utf-8'));
      if (block.hash !== computeBlockHash(block)) {
        log('Chain', `⚠ 差分sync拒否: #${block.height}ハッシュ不正`);
        cleanSyncDir(); finishSync(); return;
      }
      if (!meetsTargetDifficulty(block.hash, block.difficulty)) {
        log('Chain', `⚠ 差分sync拒否: #${block.height} PoW不正`);
        cleanSyncDir(); finishSync(); return;
      }
    }

    // 既存チェーンの先頭部分を保持しつつマージ→全体rebuild
    const mergedChain: Block[] = chain.slice(0, syncStartHeight);
    for (const file of files) {
      mergedChain.push(JSON.parse(readFileSync(`${SYNC_DIR}/${file}`, 'utf-8')));
    }

    // selectChainでワーク量比較→rebuildState
    selectChain(mergedChain);

    log('Chain', `差分sync完了: ${chain.length}ブロック`);
    cleanSyncDir();
    finishSync();
    return;
  }

  // フル同期: height 0 から始まるチェーン
  if (syncStartHeight === 0 && syncEndHeight + 1 > chain.length) {
    log('Sync', `フルrebuild開始: ${files.length}ブロック`);

    chain.length = 0;
    accounts.clear();
    tokens.clear();
    ammPools.clear();
    totalMined = "0";
    currentDifficulty = CONFIG.INITIAL_DIFFICULTY;
    lastBlockHash = '';

    isRebuilding = true;
    const verifyStart = Math.max(0, files.length - CONFIG.SYNC_VERIFY_TAIL);

    for (let i = 0; i < files.length; i++) {
      try {
        const block: Block = JSON.parse(readFileSync(`${SYNC_DIR}/${files[i]}`, 'utf-8'));

        if (i >= verifyStart) {
          const isGenesis = block.height === 0 &&
            block.previousHash === "0x0000000000000000000000000000000000000000000000000000000000000000";

          if (!isGenesis) {
            if (block.hash !== computeBlockHash(block)) {
              log('Chain', `⚠ フルrebuild拒否: #${block.height}ハッシュ不正`);
              isRebuilding = false; cleanSyncDir(); return;
            }
            if (!meetsTargetDifficulty(block.hash, block.difficulty)) {
              log('Chain', `⚠ フルrebuild拒否: #${block.height} PoW不正`);
              isRebuilding = false; cleanSyncDir(); return;
            }
          }
          if (chain.length > 0 && block.previousHash !== chain[chain.length - 1].hash) {
            log('Chain', `⚠ フルrebuild拒否: #${block.height} previousHash不一致`);
            isRebuilding = false; cleanSyncDir(); return;
          }
        }

        applyBlock(block);
      } catch (e) {
        log('Chain', `⚠ フルrebuild失敗 #${i}: ${e}`);
        isRebuilding = false; cleanSyncDir(); return;
      }
    }
    isRebuilding = false;

    log('Chain', `フルrebuild完了: ${chain.length}ブロック (末尾${CONFIG.SYNC_VERIFY_TAIL}検証済み)`);
    cleanSyncDir();
    finishSync();
    return;
  }

  // ここに来る場合: syncStartHeight > chain.length（ギャップがある）
  log('Sync', `⚠ ギャップ検出: 受信開始#${syncStartHeight} > 現在チェーン長${chain.length} → スキップ`);
  cleanSyncDir();
  finishSync();
}

// ============================================================
// シードノード接続（seeds.json ベース、ランダム選択、指数バックオフ）
// ============================================================

let seedSocket: Socket | null = null;
let seedBuffer: string = '';
let currentSeedHost: string = '';

interface SeedEntry {
  host: string;
  id: number;
}

function loadSeeds(): SeedEntry[] {
  try {
    if (existsSync('./seeds.json')) {
      const data = JSON.parse(readFileSync('./seeds.json', 'utf-8'));
      return data.seeds || [];
    }
  } catch (e) {
    log('Net', `seeds.json 読み込み失敗: ${e}`);
  }
  return [{ host: 'mail.shudo-physics.com', id: 0 }];
}

function connectToSeed(): void {
  const seeds = loadSeeds();
  if (seeds.length === 0) {
    log('Net', '❌ シードリストが空');
    return;
  }

  // 現在接続中のホスト以外からランダム選択
  const candidates = seeds.filter(s => s.host !== currentSeedHost);
  const seed = candidates.length > 0
    ? candidates[Math.floor(Math.random() * candidates.length)]
    : seeds[Math.floor(Math.random() * seeds.length)];

  currentSeedHost = seed.host;
  log('Net', `シードノードに接続中: ${seed.host}:${CONFIG.SEED_PORT} (id=${seed.id})`);

  let connected = false;

  seedSocket = connect(CONFIG.SEED_PORT, seed.host, () => {
    connected = true;
    log('Net', `✅ 接続成功: ${seed.host}`);
    sendToSeed({
      type: 'register',
      data: { chainHeight: chain.length, difficulty: currentDifficulty }
    });
    isSyncing = true;
    startSyncTimeout();
  });

  seedSocket.on('data', (data: Buffer) => {
    seedBuffer += data.toString();
    // バッファ肥大化防止
    if (seedBuffer.length > 10 * 1024 * 1024) {
      log('Net', '⚠ バッファ肥大化、クリア');
      seedBuffer = '';
      return;
    }
    const parts: string[] = seedBuffer.split(DELIMITER);
    seedBuffer = parts.pop() || '';
    for (const part of parts) {
      if (!part.trim()) continue;
      try { const packet: Packet = JSON.parse(part); handlePacket(packet); } catch {}
    }
  });

  seedSocket.on('close', () => {
    log('Net', `❌ シード切断 (${currentSeedHost}) → exit(1) でランチャーに委譲`);
    seedSocket = null;
    process.exit(1);
  });

  seedSocket.on('error', (err: Error) => {
    log('Net', `❌ 接続エラー (${seed.host}): ${err.message}`);
    if (!connected) {
      // 接続前のエラー → ソケットを破棄してexit
      seedSocket?.destroy();
      seedSocket = null;
      log('Net', '→ exit(1) でランチャーに委譲');
      process.exit(1);
    }
    // 接続後のエラーはclose側で処理される
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
  // 同期中はクライアント向けリクエストとブロードキャストを拒否（ノード間同期通信は通す）
  const blockedDuringSyncWithResponse = new Set([
    'get_balance', 'get_height', 'get_block_template', 'get_chain',
    'get_token', 'get_tokens_list', 'get_rate', 'get_mempool',
    'get_recent_transactions', 'get_block', 'tx'
  ]);
  const blockedDuringSyncSilent = new Set([
    'block_broadcast', 'tx_broadcast'
  ]);

  if (isSyncing) {
    if (blockedDuringSyncWithResponse.has(packet.type)) {
      const clientId = packet.data?.clientId;
      if (clientId) {
        sendToSeed({
          type: 'sync_busy',
          data: { clientId, message: 'ノードは同期中です。しばらくお待ちください。' }
        });
      }
      return;
    }
    if (blockedDuringSyncSilent.has(packet.type)) {
      // 同期中はブロードキャストを無視（同期完了後に正しいチェーンが確定する）
      return;
    }
  }

  switch (packet.type) {
    case 'ping':
      sendToSeed({ type: 'pong' });
      break;

    case 'node_list': {
      const nodes = packet.data?.nodes || [];
      log('Net', `ノードリスト受信: ${nodes.length}台`);
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
      const result = await verifyBlock(block);
      if (result.valid) {
        applyBlock(block);
        log('Block', `ブロック適用: #${block.height} by ${block.miner.slice(0, 10)}... (${block.transactions.length}tx)`);
        saveState();
        sendToSeed({
          type: 'block_accepted',
          data: {
            ...block,
            height: block.height,
            hash: block.hash,
            difficulty: currentDifficulty,
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
      const { clientId: _cid, ...txOnly } = packet.data;
      const tx: Transaction = txOnly;
      const result = await verifyTransaction(tx);

      if (result.valid) {
        if (pendingTxs.length >= MAX_PENDING_TXS) {
          log('Tx', `⚠ mempool上限 (${MAX_PENDING_TXS}) → 拒否`);
          if (clientId) {
            sendToSeed({ type: 'tx_result', data: { clientId, success: false, error: 'Mempool full' } });
          }
        } else {
          // pending内で同一アドレス+同一nonceが既にあるか
          const duplicate = pendingTxs.some(p => p.from === tx.from && p.nonce === tx.nonce);
          if (duplicate) {
            log('Tx', `⚠ Nonce重複(pending): ${tx.from.slice(0, 10)}... nonce=${tx.nonce}`);
            if (clientId) {
              sendToSeed({ type: 'tx_result', data: { clientId, success: false, error: `Nonce ${tx.nonce} already in mempool` } });
            }
          } else {
            pendingTxs.push(tx);
            log('Tx', `受付: ${tx.type} from ${tx.from.slice(0, 10)}... nonce=${tx.nonce}`);
            sendToSeed({ type: 'tx_broadcast', data: tx });
            if (clientId) {
              sendToSeed({ type: 'tx_result', data: { clientId, success: true, txType: tx.type, nonce: tx.nonce } });
            }
          }
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
      if (pendingTxs.length >= MAX_PENDING_TXS) break;
      const result = await verifyTransaction(tx);
      if (result.valid) {
        const sigDup: boolean = pendingTxs.some(p => p.signature === tx.signature);
        const nonceDup: boolean = pendingTxs.some(p => p.from === tx.from && p.nonce === tx.nonce);
        if (!sigDup && !nonceDup) pendingTxs.push(tx);
      }
      break;
    }

    // --- クライアント照会 ---
    case 'get_balance': {
      const clientId: string = packet.data?.clientId;
      const address: string = packet.data?.address;
      const account: Account = peekAccount(address);

      // pending考慮: account.nonceとpending内の最大nonce+1のうち大きい方
      const pendingForAddr = pendingTxs.filter(p => p.from === address);
      let pendingNonce = account.nonce;
      if (pendingForAddr.length > 0) {
        const maxPendingNonce = Math.max(...pendingForAddr.map(p => p.nonce));
        if (maxPendingNonce >= account.nonce) {
          pendingNonce = maxPendingNonce + 1;
        }
      }
      sendToSeed({
        type: 'balance',
        data: { clientId, address, balance: account.balance, nonce: account.nonce, pendingNonce, tokens: account.tokens }
      });
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
      const reward: string = calculateReward(chain.length);

      // pendingTxsからnonce整合性のあるTXだけ選別
      const validTxs = selectValidTxsForBlock(pendingTxs);

      sendToSeed({
        type: 'block_template',
        data: {
          clientId, height: chain.length, previousHash: latestHash,
          difficulty: currentDifficulty, reward, transactions: validTxs, miner,
        }
      });
      break;
    }

    case 'get_chain': {
      const clientId: string = packet.data?.clientId;
      let from: number = packet.data?.from || 0;
      let to: number = packet.data?.to || chain.length;
      if (from < 0) { from = Math.max(0, chain.length + from); to = chain.length; }
      if (to - from > 200) to = from + 200;
      const chunk: Block[] = chain.slice(from, to);
      sendToSeed({ type: 'chain_chunk', data: { clientId, from, to, blocks: chunk } });
      break;
    }

    case 'get_token': {
      const clientId: string = packet.data?.clientId;
      const tokenAddress: string = packet.data?.address;
      const token: TokenInfo | undefined = tokens.get(tokenAddress);
      sendToSeed({ type: 'token_info', data: { clientId, token: token || null } });
      break;
    }

    case 'get_tokens_list': {
      const clientId: string = packet.data?.clientId;
      const list = Array.from(tokens.values()).map(t => ({
        address: t.address, symbol: t.symbol, name: t.name, totalSupply: t.totalSupply
      }));
      sendToSeed({ type: 'tokens_list', data: { clientId, tokens: list } });
      break;
    }

    case 'get_rate': {
      const clientId: string = packet.data?.clientId;
      const tokenAddress: string = packet.data?.address;
      const minute: number = Math.floor(Date.now() / 60000);
      const rate: string = getFluctuatedRate(tokenAddress, minute);
      sendToSeed({ type: 'rate', data: { clientId, tokenAddress, rate, minute } });
      break;
    }

    case 'get_mempool': {
      const clientId: string = packet.data?.clientId;
      sendToSeed({
        type: 'mempool',
        data: { clientId, count: pendingTxs.length, transactions: pendingTxs.slice(0, 50) }
      });
      break;
    }

    case 'get_recent_transactions': {
      const clientId: string = packet.data?.clientId;
      const limit: number = Math.min(packet.data?.limit || 50, 200);
      const recentTxs: Transaction[] = [];
      for (let i = chain.length - 1; i >= 0 && recentTxs.length < limit; i--) {
        for (const tx of chain[i].transactions) {
          if (recentTxs.length >= limit) break;
          recentTxs.push(tx);
        }
      }
      sendToSeed({ type: 'transactions', data: { clientId, transactions: recentTxs } });
      break;
    }

    case 'get_block': {
      const clientId: string = packet.data?.clientId;
      const height: number = packet.data?.height;
      if (height >= 0 && height < chain.length) {
        sendToSeed({ type: 'block', data: { clientId, block: chain[height] } });
      } else {
        sendToSeed({ type: 'block', data: { clientId, block: null, error: 'ブロックが見つかりません' } });
      }
      break;
    }

    // admin系・random系は v3.0 で全廃

    // --- チェーン同期 ---
    case 'send_chain_to': {
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
            data: { targetNodeId, blocks: chunk, chunkIndex, totalChunks, totalHeight: chain.length }
          });
        }
        log('Sync', `チェーン送信: → ${targetNodeId} (${fromHeight}〜${chain.length})`);
      }
      break;
    }

    case 'chain_sync': {
      const blocks: Block[] = packet.data?.blocks;
      if (!blocks || blocks.length === 0) break;
      const chunkIndex: number = packet.data?.chunkIndex || 1;
      const totalChunks: number = packet.data?.totalChunks || 1;
      const totalHeight: number = packet.data?.totalHeight || 0;

      // 基本サニティチェック
      let valid = true;
      for (const b of blocks) {
        if (typeof b.height !== 'number' || !b.hash || !b.previousHash) {
          log('Sync', `⚠ 不正ブロック検出: height=${b.height}`);
          valid = false;
          break;
        }
      }
      if (!valid) break;

      // チャンクごとに即ディスク書き出し
      writeSyncBlocks(blocks);
      syncReceivedBlocks += blocks.length;
      syncExpectedHeight = totalHeight;

      log('Sync', `チャンク受信: ${chunkIndex}/${totalChunks} (${blocks.length}ブロック, 累計${syncReceivedBlocks})`);

      if (syncTimer) clearTimeout(syncTimer);
      startSyncTimeout();

      // 全チャンク到着 → ディスクからストリーミングrebuild
      if (chunkIndex >= totalChunks || syncReceivedBlocks >= totalHeight) {
        log('Sync', `全チャンク受信完了: ${syncReceivedBlocks}ブロック → ディスクからrebuild`);
        applySyncedChain();
      }
      break;
    }

    case 'chain_sync_response': {
      const blocks: Block[] = packet.data?.blocks;
      if (!blocks || blocks.length === 0) { log('Sync', 'フォールバック応答: ブロックなし'); finishSync(); break; }
      log('Sync', `フォールバック受信: ${blocks.length}ブロック`);
      blocks.sort((a, b) => a.height - b.height);
      if (blocks.length > chain.length) {
        if (blocks[0].height === 0) selectChain(blocks);
        else if (blocks[0].height <= chain.length) {
          const merged = [...chain.slice(0, blocks[0].height), ...blocks];
          selectChain(merged);
        }
      }
      finishSync();
      break;
    }

    case 'send_chain_direct': {
      const targetNodeId: string = packet.data?.targetNodeId;
      const fromHeight: number = packet.data?.fromHeight || 0;
      if (chain.length > fromHeight) {
        // send_chain_toと同じチャンク分割方式
        const CHUNK_SIZE = 50;
        const slice = chain.slice(fromHeight);
        const totalChunks = Math.ceil(slice.length / CHUNK_SIZE);
        for (let i = 0; i < slice.length; i += CHUNK_SIZE) {
          const chunk = slice.slice(i, i + CHUNK_SIZE);
          sendToSeed({ type: 'chain_sync_direct', data: { targetNodeId, blocks: chunk } });
        }
        log('Sync', `フォールバック送信: → ${targetNodeId} (${slice.length}ブロック, ${totalChunks}チャンク)`);
      }
      break;
    }

    case 'sync_needed': {
      log('Sync', `同期要求受信: 現在=${chain.length}, ネットワーク最長=${packet.data?.bestHeight || '?'}`);
      if (!isSyncing) {
        isSyncing = true;
        syncReceivedBlocks = 0;
        syncExpectedHeight = 0;
        cleanSyncDir();
        startSyncTimeout();
      }
      break;
    }

    default:
      break;
  }
}

// ============================================================
// 定期処理
// ============================================================

function startPeriodicTasks(): void {
  setInterval(() => {
    sendToSeed({ type: 'height', data: { height: chain.length, difficulty: currentDifficulty } });
  }, 30000);

  setInterval(() => { saveState(); }, 60000);

  setInterval(() => {
    log('Stats', `チェーン: ${chain.length}ブロック, アカウント: ${accounts.size}, pending: ${pendingTxs.length}, 発行済: ${weiToBtrDisplay(totalMined)} BTR`);
  }, 60000);

  setInterval(() => {
    if (!isSyncing) {
      sendToSeed({ type: 'check_sync', data: { height: chain.length } });
    }
  }, 120000);

  // pendingTxs クリーンアップ（5分ごと）
  setInterval(() => {
    const now = Date.now();
    const TIMEOUT = 3600000;
    const oldCount = pendingTxs.length;
    const filtered = pendingTxs.filter(tx => now - tx.timestamp < TIMEOUT);
    pendingTxs.length = 0;
    pendingTxs.push(...filtered);
    const removed = oldCount - pendingTxs.length;
    if (removed > 0) log('Mempool', `古いTx削除: ${removed}件`);
  }, 300000);
}

// ============================================================
// エントリーポイント
// ============================================================

function main(): void {
  console.log('========================================');
  console.log('  BTR (Buturi Coin) Full Node v3.0');
  console.log('  BigInt Edition (Wei = 10^18)');
  console.log('  LWMA + Streaming Sync');
  console.log('========================================');

  loadState();
  cleanSyncDir();  // 前回の同期残骸をクリア

  connectToSeed();
  startPeriodicTasks();

  const seeds = loadSeeds();
  log('Init', `フルノード起動完了 (BigInt版)`);
  log('Init', `チェーン高さ: ${chain.length}, 難易度: ${currentDifficulty}`);
  log('Init', `シードノード: ${seeds.length}件 (${seeds.map(s => s.host).join(', ')})`);
}

// プロセス例外ハンドラ（クラッシュ防止、launcherの再起動に頼らない）
process.on('uncaughtException', (err) => {
  log('Fatal', `未キャッチ例外: ${err.message}\n${err.stack}`);
});
process.on('unhandledRejection', (reason) => {
  log('Fatal', `未処理Promise拒否: ${reason}`);
});

main();