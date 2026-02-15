// ============================================================
// BTR (Buturi Coin) - フルノード BigInt完全対応版
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
  CDN_SEEDS_URL: 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/fullserver/seeds.json',
  CHAIN_FILE: './chain.json',
  ACCOUNTS_FILE: './accounts.json',
  TOKENS_FILE: './tokens.json',
  PENDING_FILE: './pending.json',
  AMM_FILE: './amm.json',
  TRUSTED_KEYS_FILE: './trusted_keys.json',
  SEEDS_FILE: './seeds.json',
  BLOCK_TIME: 30000,
  MAX_DIFFICULTY: 6,
  INITIAL_DIFFICULTY: 1,
  DIFFICULTY_DROP_TIME: 90000,
  REWARD_BASE: 100n * WEI_PER_BTR,
  REWARD_HALVING: 210000,
  GAS_FEE_WEI: 1n * WEI_PER_BTR,
  TOKEN_CREATE_FEE_WEI: 500n * WEI_PER_BTR,
  SYNC_TIMEOUT: 10000,
};

function btrToWei(btr: number | string): string {
  if (typeof btr === 'string') btr = parseFloat(btr);
  if (isNaN(btr) || btr < 0) return "0";
  const str = btr.toFixed(18);
  const [wholePart, fracPart = ''] = str.split('.');
  const whole = BigInt(wholePart) * WEI_PER_BTR;
  const frac = BigInt(fracPart.padEnd(18, '0').slice(0, 18));
  return (whole + frac).toString();
}

function weiToBtrDisplay(wei: string | bigint): string {
  try {
    const weiNum = typeof wei === 'string' ? BigInt(wei) : wei;
    if (weiNum < 0n) return "0";
    const whole = weiNum / WEI_PER_BTR;
    const fraction = weiNum % WEI_PER_BTR;
    const fractionStr = fraction.toString().padStart(18, '0');
    const trimmed = fractionStr.slice(0, 6).replace(/0+$/, '');
    if (trimmed === '') return whole.toString();
    return `${whole}.${trimmed}`;
  } catch { return "0"; }
}

function compareWei(a: string, b: string): number {
  const diff = BigInt(a || "0") - BigInt(b || "0");
  if (diff > 0n) return 1; if (diff < 0n) return -1; return 0;
}

// ============================================================
// 型定義
// ============================================================

interface Seed { host: string; port: number; }
interface Transaction {
  from: string; to: string; amount: string; nonce: number; timestamp: number;
  signature: string; publicKey: string; type: 'transfer' | 'token_transfer' | 'token_create' | 'swap' | 'coinbase';
  token?: string; tokenAmount?: string; tokenSymbol?: string; tokenName?: string;
  tokenSupply?: string; swapIn?: string; swapOut?: string;
}
interface Block {
  height: number; timestamp: number; miner: string; nonce: number;
  previousHash: string; difficulty: number; hash: string;
  transactions: Transaction[]; reward: string;
}
interface TokenInfo { symbol: string; name: string; totalSupply: string; owner: string; }
interface Packet { type: string; data?: any; }

// ============================================================
// グローバル状態
// ============================================================

let chain: Block[] = [];
let accounts: Map<string, string> = new Map();
let tokens: Map<string, Map<string, string>> = new Map();
let tokensInfo: Map<string, TokenInfo> = new Map();
let pendingTxs: Transaction[] = [];
let ammPools: Map<string, { token0: string; token1: string; reserve0: string; reserve1: string }> = new Map();

let currentDifficulty: number = CONFIG.INITIAL_DIFFICULTY;
let totalMined: bigint = 0n;
let lastBlockTime: number = Date.now();
let difficultyDropTimer: NodeJS.Timeout | null = null;

let seedSocket: Socket | null = null;
let clientId: string = '';
let commonRandom: string = '';
let isSyncing: boolean = false;
let syncBuffer: Block[] = [];
let syncTimer: NodeJS.Timeout | null = null;
let lastSeedsHash: string = '';

// ============================================================
// ヘルパー
// ============================================================

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf-8').digest('hex');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function canonicalJSON(obj: any): string {
  if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys: string[] = Object.keys(obj).sort();
  const pairs: string[] = keys.map(k => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`);
  return '{' + pairs.join(',') + '}';
}

function log(category: string, msg: string): void {
  const now = new Date();
  const time = now.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  console.log(`[${time}] [${category}] ${msg}`);
}

async function verifySignature(tx: Transaction): Promise<boolean> {
  try {
    const { signature, publicKey, ...rest } = tx;
    const canonical = canonicalJSON(rest);
    const msgBytes = new TextEncoder().encode(canonical);
    const sigBytes = hexToBytes(signature);
    const pubBytes = hexToBytes(publicKey);
    return await Ed25519.verify(sigBytes, msgBytes, pubBytes);
  } catch { return false; }
}

function deriveAddress(publicKey: string): string {
  const keyHash = sha256(publicKey);
  return `0x${keyHash.slice(-16)}`;
}

// ============================================================
// ブロック生成・検証
// ============================================================

function getBlockReward(height: number): string {
  const halvings = Math.floor(height / CONFIG.REWARD_HALVING);
  const reward = CONFIG.REWARD_BASE / (2n ** BigInt(halvings));
  if (reward < 1n) return "1";
  return reward.toString();
}

function calculateBlockHash(block: Block): string {
  const { hash, ...rest } = block;
  return sha256(canonicalJSON(rest));
}

function verifyDifficulty(hash: string, difficulty: number): boolean {
  const prefix = '0'.repeat(difficulty);
  return hash.startsWith(prefix);
}

async function isValidBlock(block: Block): Promise<boolean> {
  if (block.height !== chain.length) return false;
  if (block.previousHash !== (chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64))) return false;
  const hash = calculateBlockHash(block);
  if (hash !== block.hash) return false;
  if (!verifyDifficulty(hash, block.difficulty)) return false;
  const expectedReward = getBlockReward(block.height);
  if (block.reward !== expectedReward) return false;
  for (const tx of block.transactions) {
    if (tx.type === 'coinbase') continue;
    if (!(await verifySignature(tx))) return false;
    const fromAddr = deriveAddress(tx.publicKey);
    if (fromAddr !== tx.from) return false;
  }
  return true;
}

function createCoinbaseTx(miner: string, reward: string): Transaction {
  return {
    from: BTR_ADDRESS, to: miner, amount: reward, nonce: 0, timestamp: Date.now(),
    signature: '', publicKey: '', type: 'coinbase'
  };
}

// ============================================================
// 状態適用
// ============================================================

function applyBlock(block: Block): void {
  for (const tx of block.transactions) {
    if (tx.type === 'coinbase') {
      const current = accounts.get(tx.to) || "0";
      accounts.set(tx.to, (BigInt(current) + BigInt(tx.amount)).toString());
      continue;
    }

    switch (tx.type) {
      case 'transfer': {
        const fromBal = BigInt(accounts.get(tx.from) || "0");
        const toBal = BigInt(accounts.get(tx.to) || "0");
        const amount = BigInt(tx.amount);
        const gas = CONFIG.GAS_FEE_WEI;
        if (fromBal < amount + gas) continue;
        accounts.set(tx.from, (fromBal - amount - gas).toString());
        accounts.set(tx.to, (toBal + amount).toString());
        accounts.set(block.miner, (BigInt(accounts.get(block.miner) || "0") + gas).toString());
        break;
      }

      case 'token_transfer': {
        if (!tx.token || !tx.tokenAmount) continue;
        const tMap = tokens.get(tx.token);
        if (!tMap) continue;
        const fromBal = BigInt(tMap.get(tx.from) || "0");
        const toBal = BigInt(tMap.get(tx.to) || "0");
        const amount = BigInt(tx.tokenAmount);
        if (fromBal < amount) continue;
        const btrFrom = BigInt(accounts.get(tx.from) || "0");
        const gas = CONFIG.GAS_FEE_WEI;
        if (btrFrom < gas) continue;
        accounts.set(tx.from, (btrFrom - gas).toString());
        accounts.set(block.miner, (BigInt(accounts.get(block.miner) || "0") + gas).toString());
        tMap.set(tx.from, (fromBal - amount).toString());
        tMap.set(tx.to, (toBal + amount).toString());
        break;
      }

      case 'token_create': {
        if (!tx.token || !tx.tokenSymbol || !tx.tokenName || !tx.tokenSupply) continue;
        const btrBal = BigInt(accounts.get(tx.from) || "0");
        const fee = CONFIG.TOKEN_CREATE_FEE_WEI + CONFIG.GAS_FEE_WEI;
        if (btrBal < fee) continue;
        accounts.set(tx.from, (btrBal - fee).toString());
        accounts.set(block.miner, (BigInt(accounts.get(block.miner) || "0") + CONFIG.GAS_FEE_WEI).toString());
        tokensInfo.set(tx.token, { symbol: tx.tokenSymbol, name: tx.tokenName, totalSupply: tx.tokenSupply, owner: tx.from });
        const tMap = new Map<string, string>();
        tMap.set(tx.from, tx.tokenSupply);
        tokens.set(tx.token, tMap);
        const poolId = `${BTR_ADDRESS}:${tx.token}`;
        ammPools.set(poolId, { token0: BTR_ADDRESS, token1: tx.token, reserve0: btrToWei(500), reserve1: tx.tokenSupply });
        break;
      }

      case 'swap': {
        if (!tx.swapIn || !tx.swapOut || !tx.amount) continue;
        const poolId = tx.swapIn < tx.swapOut ? `${tx.swapIn}:${tx.swapOut}` : `${tx.swapOut}:${tx.swapIn}`;
        const pool = ammPools.get(poolId);
        if (!pool) continue;
        const isToken0 = (tx.swapIn === pool.token0);
        const [rIn, rOut] = isToken0 ? [BigInt(pool.reserve0), BigInt(pool.reserve1)] : [BigInt(pool.reserve1), BigInt(pool.reserve0)];
        const amountIn = BigInt(tx.amount);
        const amountOut = (rOut * amountIn) / (rIn + amountIn);
        const fromBal = (tx.swapIn === BTR_ADDRESS) ? BigInt(accounts.get(tx.from) || "0") : BigInt((tokens.get(tx.swapIn)?.get(tx.from)) || "0");
        const toBal = (tx.swapOut === BTR_ADDRESS) ? BigInt(accounts.get(tx.from) || "0") : BigInt((tokens.get(tx.swapOut)?.get(tx.from)) || "0");
        if (fromBal < amountIn) continue;
        const btrBal = BigInt(accounts.get(tx.from) || "0");
        const gas = CONFIG.GAS_FEE_WEI;
        if (btrBal < gas) continue;
        accounts.set(tx.from, (btrBal - gas).toString());
        accounts.set(block.miner, (BigInt(accounts.get(block.miner) || "0") + gas).toString());
        if (tx.swapIn === BTR_ADDRESS) accounts.set(tx.from, (fromBal - amountIn).toString());
        else tokens.get(tx.swapIn)!.set(tx.from, (fromBal - amountIn).toString());
        if (tx.swapOut === BTR_ADDRESS) accounts.set(tx.from, (toBal + amountOut).toString());
        else {
          const tMap = tokens.get(tx.swapOut);
          if (!tMap) continue;
          tMap.set(tx.from, (toBal + amountOut).toString());
        }
        if (isToken0) {
          pool.reserve0 = (rIn + amountIn).toString();
          pool.reserve1 = (rOut - amountOut).toString();
        } else {
          pool.reserve1 = (rIn + amountIn).toString();
          pool.reserve0 = (rOut - amountOut).toString();
        }
        break;
      }
    }
  }
}

function addBlock(block: Block): boolean {
  applyBlock(block);
  chain.push(block);
  totalMined += BigInt(block.reward);
  pendingTxs = pendingTxs.filter(tx => !block.transactions.some(btx => btx.signature === tx.signature));
  lastBlockTime = Date.now();
  adjustDifficultyAfterBlock();
  log('Block', `ブロック追加: #${block.height}, 難易度: ${block.difficulty}, 報酬: ${weiToBtrDisplay(block.reward)} BTR`);
  return true;
}

// ============================================================
// 難易度調整
// ============================================================

function adjustDifficultyAfterBlock(): void {
  const timeSinceLastBlock = Date.now() - lastBlockTime;
  if (timeSinceLastBlock < CONFIG.BLOCK_TIME && currentDifficulty < CONFIG.MAX_DIFFICULTY) {
    currentDifficulty++;
    log('Difficulty', `難易度上昇: ${currentDifficulty}`);
    broadcastDifficultyUpdate(); // 追加: 難易度変更をブロードキャスト
  } else if (timeSinceLastBlock > CONFIG.BLOCK_TIME * 2 && currentDifficulty > 1) {
    currentDifficulty = Math.max(1, currentDifficulty - 1);
    log('Difficulty', `難易度降下: ${currentDifficulty}`);
    broadcastDifficultyUpdate(); // 追加: 難易度変更をブロードキャスト
  }
  resetDifficultyDropTimer();
}

function resetDifficultyDropTimer(): void {
  if (difficultyDropTimer) clearTimeout(difficultyDropTimer);
  difficultyDropTimer = setTimeout(() => {
    if (currentDifficulty > CONFIG.INITIAL_DIFFICULTY) {
      currentDifficulty = CONFIG.INITIAL_DIFFICULTY;
      log('Difficulty', `タイムアウトで難易度リセット: ${currentDifficulty}`);
      broadcastDifficultyUpdate(); // 追加: 難易度変更をブロードキャスト
    }
  }, CONFIG.DIFFICULTY_DROP_TIME);
}

// 追加: 難易度変更をブロードキャスト
function broadcastDifficultyUpdate(): void {
  const latestBlock = chain.length > 0 ? chain[chain.length - 1] : null;
  const reward = getBlockReward(chain.length);
  sendToSeed({
    type: 'broadcast',
    data: {
      type: 'difficulty_update',
      difficulty: currentDifficulty,
      latestBlockHash: latestBlock ? latestBlock.hash : '0'.repeat(64),
      reward: reward
    }
  });
}

// ============================================================
// Tx検証
// ============================================================

async function isValidTransaction(tx: Transaction): Promise<boolean> {
  if (tx.type === 'coinbase') return true;
  if (!(await verifySignature(tx))) return false;
  const fromAddr = deriveAddress(tx.publicKey);
  if (fromAddr !== tx.from) return false;

  switch (tx.type) {
    case 'transfer': {
      const bal = BigInt(accounts.get(tx.from) || "0");
      const amount = BigInt(tx.amount);
      const gas = CONFIG.GAS_FEE_WEI;
      if (bal < amount + gas) return false;
      break;
    }
    case 'token_transfer': {
      if (!tx.token || !tx.tokenAmount) return false;
      const tMap = tokens.get(tx.token);
      if (!tMap) return false;
      const bal = BigInt(tMap.get(tx.from) || "0");
      const amount = BigInt(tx.tokenAmount);
      if (bal < amount) return false;
      const btrBal = BigInt(accounts.get(tx.from) || "0");
      if (btrBal < CONFIG.GAS_FEE_WEI) return false;
      break;
    }
    case 'token_create': {
      if (!tx.token || !tx.tokenSymbol || !tx.tokenName || !tx.tokenSupply) return false;
      if (tokensInfo.has(tx.token)) return false;
      const bal = BigInt(accounts.get(tx.from) || "0");
      const fee = CONFIG.TOKEN_CREATE_FEE_WEI + CONFIG.GAS_FEE_WEI;
      if (bal < fee) return false;
      break;
    }
    case 'swap': {
      if (!tx.swapIn || !tx.swapOut || !tx.amount) return false;
      const poolId = tx.swapIn < tx.swapOut ? `${tx.swapIn}:${tx.swapOut}` : `${tx.swapOut}:${tx.swapIn}`;
      if (!ammPools.has(poolId)) return false;
      const fromBal = (tx.swapIn === BTR_ADDRESS)
        ? BigInt(accounts.get(tx.from) || "0")
        : BigInt((tokens.get(tx.swapIn)?.get(tx.from)) || "0");
      const amount = BigInt(tx.amount);
      if (fromBal < amount) return false;
      const btrBal = BigInt(accounts.get(tx.from) || "0");
      if (btrBal < CONFIG.GAS_FEE_WEI) return false;
      break;
    }
  }
  return true;
}

// ============================================================
// チェーン選択
// ============================================================

function selectChain(newChain: Block[]): void {
  if (newChain.length <= chain.length) return;
  log('Sync', `チェーン切り替え: ${chain.length} → ${newChain.length}`);
  chain = [];
  accounts.clear();
  tokens.clear();
  tokensInfo.clear();
  ammPools.clear();
  totalMined = 0n;
  for (const block of newChain) {
    applyBlock(block);
    chain.push(block);
    totalMined += BigInt(block.reward);
  }
  if (chain.length > 0) {
    lastBlockTime = chain[chain.length - 1].timestamp;
    currentDifficulty = chain[chain.length - 1].difficulty;
  }
  saveState();
}

// ============================================================
// 保存・読み込み
// ============================================================

function saveState(): void {
  try {
    writeFileSync(CONFIG.CHAIN_FILE, JSON.stringify(chain, null, 2));
    writeFileSync(CONFIG.ACCOUNTS_FILE, JSON.stringify(Array.from(accounts.entries()), null, 2));
    const tokensArr = Array.from(tokens.entries()).map(([addr, map]) => [addr, Array.from(map.entries())]);
    writeFileSync(CONFIG.TOKENS_FILE, JSON.stringify(tokensArr, null, 2));
    writeFileSync(CONFIG.PENDING_FILE, JSON.stringify(pendingTxs, null, 2));
    const ammArr = Array.from(ammPools.entries());
    writeFileSync(CONFIG.AMM_FILE, JSON.stringify(ammArr, null, 2));
    log('State', '状態保存完了');
  } catch (err: any) {
    log('Error', `状態保存失敗: ${err.message}`);
  }
}

function loadState(): void {
  try {
    if (existsSync(CONFIG.CHAIN_FILE)) {
      chain = JSON.parse(readFileSync(CONFIG.CHAIN_FILE, 'utf-8'));
      if (chain.length > 0) {
        lastBlockTime = chain[chain.length - 1].timestamp;
        currentDifficulty = chain[chain.length - 1].difficulty;
      }
      for (const block of chain) {
        applyBlock(block);
        totalMined += BigInt(block.reward);
      }
    }
    if (existsSync(CONFIG.ACCOUNTS_FILE)) {
      const arr: [string, string][] = JSON.parse(readFileSync(CONFIG.ACCOUNTS_FILE, 'utf-8'));
      accounts = new Map(arr);
    }
    if (existsSync(CONFIG.TOKENS_FILE)) {
      const arr: [string, [string, string][]][] = JSON.parse(readFileSync(CONFIG.TOKENS_FILE, 'utf-8'));
      for (const [addr, entries] of arr) tokens.set(addr, new Map(entries));
    }
    if (existsSync(CONFIG.PENDING_FILE)) {
      pendingTxs = JSON.parse(readFileSync(CONFIG.PENDING_FILE, 'utf-8'));
    }
    if (existsSync(CONFIG.AMM_FILE)) {
      const arr: [string, any][] = JSON.parse(readFileSync(CONFIG.AMM_FILE, 'utf-8'));
      ammPools = new Map(arr);
    }
    log('State', `状態読み込み完了: ${chain.length}ブロック, ${accounts.size}アカウント`);
  } catch (err: any) {
    log('Error', `状態読み込み失敗: ${err.message}`);
  }
}

function loadSeeds(): Seed[] {
  try {
    if (existsSync(CONFIG.SEEDS_FILE)) {
      return JSON.parse(readFileSync(CONFIG.SEEDS_FILE, 'utf-8'));
    }
  } catch {}
  return [{ host: 'shudo-physics.f5.si', port: CONFIG.SEED_PORT }];
}

// ============================================================
// シード接続
// ============================================================

function sendToSeed(packet: Packet): void {
  if (!seedSocket || seedSocket.destroyed) return;
  try {
    const msg = JSON.stringify(packet) + DELIMITER;
    seedSocket.write(msg, 'utf-8');
  } catch (err: any) {
    log('Error', `送信失敗: ${err.message}`);
  }
}

function connectToSeed(): void {
  const seeds = loadSeeds();
  if (seeds.length === 0) { log('Error', 'シードノードが見つかりません'); setTimeout(connectToSeed, 5000); return; }
  const seed = seeds[0];
  log('Seed', `シードノード接続中: ${seed.host}:${seed.port}`);
  seedSocket = connect(seed.port, seed.host, () => {
    log('Seed', `シードノード接続成功`);
    sendToSeed({ type: 'register', data: { role: 'fullnode' } });
  });

  let buffer = '';
  seedSocket.on('data', (chunk: Buffer) => {
    buffer += chunk.toString('utf-8');
    const parts = buffer.split(DELIMITER);
    buffer = parts.pop() || '';
    for (const part of parts) {
      if (!part.trim()) continue;
      try { handleSeedPacket(JSON.parse(part)); } catch {}
    }
  });

  seedSocket.on('close', () => {
    log('Seed', '切断、5秒後に再接続...');
    seedSocket = null;
    setTimeout(connectToSeed, 5000);
  });

  seedSocket.on('error', (err: Error) => {
    log('Error', `シード接続エラー: ${err.message}`);
  });
}

function startSyncTimeout(): void {
  if (syncTimer) clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    log('Sync', 'タイムアウト、フォールバック');
    sendToSeed({ type: 'request_chain_fallback', data: { fromHeight: chain.length } });
    setTimeout(finishSync, 5000);
  }, CONFIG.SYNC_TIMEOUT);
}

function finishSync(): void {
  if (syncTimer) { clearTimeout(syncTimer); syncTimer = null; }
  isSyncing = false;
  log('Sync', '同期完了');
}

// ============================================================
// シードからのパケット処理
// ============================================================

function handleSeedPacket(packet: Packet): void {
  switch (packet.type) {
    case 'registered': {
      clientId = packet.data?.clientId || '';
      log('Seed', `登録完了: ${clientId}`);
      sendToSeed({ type: 'height', data: { height: chain.length, difficulty: currentDifficulty } });
      break;
    }

    case 'new_transaction': {
      const tx: Transaction = packet.data;
      if (pendingTxs.some(t => t.signature === tx.signature)) break;
      isValidTransaction(tx).then(valid => {
        if (valid) {
          pendingTxs.push(tx);
          log('Tx', `Tx受信: ${tx.type} from ${tx.from.slice(0, 10)}...`);
        }
      });
      break;
    }

    case 'submit_block': {
      const block: Block = packet.data;
      const submitterId = packet.data?.submitterId; // 追加: 送信者のIDを取得
      isValidBlock(block).then(valid => {
        if (valid && addBlock(block)) {
          log('Block', `ブロック受理: #${block.height} by ${block.miner.slice(0, 10)}...`);
          sendToSeed({ type: 'block_accepted', data: { height: block.height } });
          
          // 追加: ブロック承認の返答を送信者に送る
          if (submitterId) {
            sendToSeed({
              type: 'block_submit_response',
              data: {
                targetClientId: submitterId,
                success: true,
                height: block.height,
                hash: block.hash
              }
            });
          }
        } else {
          log('Block', `ブロック拒否: 検証失敗`);
          
          // 追加: ブロック拒否の返答を送信者に送る
          if (submitterId) {
            sendToSeed({
              type: 'block_submit_response',
              data: {
                targetClientId: submitterId,
                success: false,
                reason: 'validation_failed'
              }
            });
          }
        }
      });
      break;
    }

    case 'request_balance': {
      const addr = packet.data?.address;
      const balance = accounts.get(addr) || "0";
      const targetClientId = packet.data?.clientId;
      sendToSeed({ type: 'balance_response', data: { targetClientId, address: addr, balance } });
      break;
    }

    case 'request_token_balance': {
      const addr = packet.data?.address;
      const token = packet.data?.token;
      const tMap = tokens.get(token);
      const balance = tMap?.get(addr) || "0";
      const targetClientId = packet.data?.clientId;
      sendToSeed({ type: 'token_balance_response', data: { targetClientId, address: addr, token, balance } });
      break;
    }

    case 'request_token_info': {
      const token = packet.data?.token;
      const info = tokensInfo.get(token) || null;
      const targetClientId = packet.data?.clientId;
      sendToSeed({ type: 'token_info_response', data: { targetClientId, token, info } });
      break;
    }

    case 'request_height': {
      const targetClientId = packet.data?.clientId;
      sendToSeed({ type: 'height_response', data: { targetClientId, height: chain.length, difficulty: currentDifficulty } });
      break;
    }

    case 'request_latest_block': {
      const targetClientId = packet.data?.clientId;
      const latestBlock = chain.length > 0 ? chain[chain.length - 1] : null;
      const reward = getBlockReward(chain.length);
      sendToSeed({
        type: 'latest_block_response',
        data: {
          targetClientId,
          latestBlockHash: latestBlock ? latestBlock.hash : '0'.repeat(64),
          difficulty: currentDifficulty,
          reward: reward
        }
      });
      break;
    }

    case 'request_pending_txs': {
      const targetClientId = packet.data?.clientId;
      sendToSeed({ type: 'pending_txs_response', data: { targetClientId, transactions: pendingTxs } });
      break;
    }

    case 'request_swap_rate': {
      const tokenIn = packet.data?.tokenIn;
      const tokenOut = packet.data?.tokenOut;
      const amountIn = packet.data?.amountIn;
      const targetClientId = packet.data?.clientId;
      const poolId = tokenIn < tokenOut ? `${tokenIn}:${tokenOut}` : `${tokenOut}:${tokenIn}`;
      const pool = ammPools.get(poolId);
      if (!pool) {
        sendToSeed({ type: 'swap_rate_response', data: { targetClientId, rate: null } });
        break;
      }
      const isToken0 = (tokenIn === pool.token0);
      const [rIn, rOut] = isToken0 ? [BigInt(pool.reserve0), BigInt(pool.reserve1)] : [BigInt(pool.reserve1), BigInt(pool.reserve0)];
      const amtIn = BigInt(amountIn);
      const amountOut = (rOut * amtIn) / (rIn + amtIn);
      sendToSeed({ type: 'swap_rate_response', data: { targetClientId, rate: amountOut.toString() } });
      break;
    }

    case 'search_token': {
      const query = packet.data?.query?.toLowerCase() || '';
      const targetClientId = packet.data?.clientId;
      const results: { address: string; symbol: string; name: string }[] = [];
      for (const [addr, info] of tokensInfo.entries()) {
        if (info.symbol.toLowerCase().includes(query) || info.name.toLowerCase().includes(query)) {
          results.push({ address: addr, symbol: info.symbol, name: info.name });
        }
      }
      sendToSeed({ type: 'token_search_response', data: { targetClientId, results } });
      break;
    }

    case 'admin_request': {
      sendToSeed({
        type: 'admin_status',
        data: {
          clientId,
          chainHeight: chain.length,
          difficulty: currentDifficulty,
          accounts: accounts.size,
          tokens: tokens.size,
          pendingTxs: pendingTxs.length,
          totalMined: weiToBtrDisplay(totalMined),
          totalMinedWei: totalMined,
        }
      });
      break;
    }

    case 'random_request': {
      const myRandom: string = randomBytes(32).toString('hex');
      const commit: string = sha256(myRandom);
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

      log('Sync', `チャンク受信: ${chunkIndex}/${totalChunks} (${blocks.length}ブロック)`);
      syncBuffer.push(...blocks);
      if (syncTimer) clearTimeout(syncTimer);
      startSyncTimeout();

      if (chunkIndex >= totalChunks || syncBuffer.length >= totalHeight) {
        log('Sync', `全チャンク受信完了: ${syncBuffer.length}ブロック`);
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
        const blocks: Block[] = chain.slice(fromHeight);
        sendToSeed({ type: 'chain_sync_direct', data: { targetNodeId, blocks } });
        log('Sync', `フォールバック送信: → ${targetNodeId} (${blocks.length}ブロック)`);
      }
      break;
    }

    case 'update': {
      log('Update', `アップデート受信: v${packet.data?.version}`);
      if (process.send) {
        process.send({ type: 'update', data: packet.data });
      }
      break;
    }

    case 'sync_trusted_keys': {
      writeFileSync('./trusted_keys.json', JSON.stringify(packet.data, null, 2));
      log('Trust', 'trusted_keys.json 同期');
      break;
    }

    case 'sync_needed': {
      log('Sync', `同期要求受信: 現在=${chain.length}, ネットワーク最長=${packet.data?.bestHeight || '?'}`);
      if (!isSyncing) {
        isSyncing = true;
        syncBuffer = [];
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
  console.log('  BTR (Buturi Coin) Full Node v2.0.2');
  console.log('  BigInt Edition (Wei = 10^18)');
  console.log('========================================');

  loadState();

  // 初回seeds.jsonハッシュ記録
  try {
    if (existsSync('./seeds.json')) {
      lastSeedsHash = sha256(readFileSync('./seeds.json', 'utf-8'));
    }
  } catch {}

  connectToSeed();
  startPeriodicTasks();
  resetDifficultyDropTimer();

  const seeds = loadSeeds();
  log('Init', `フルノード起動完了 (BigInt版)`);
  log('Init', `チェーン高さ: ${chain.length}, 難易度: ${currentDifficulty}`);
  log('Init', `シードノード: ${seeds.length}件 (${seeds.map(s => s.host).join(', ')})`);
}

main();