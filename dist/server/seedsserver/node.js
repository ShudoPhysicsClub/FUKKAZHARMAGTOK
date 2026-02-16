// ============================================================
// BTR (Buturi Coin) - フルノード v2.1.0 BigInt完全対応版
// LWMA難易度調整 / 同期中通信遮断 / チェーンベース難易度検証
// ランチャーからforkされて動く
// 全金額は Wei文字列 (1 BTR = 10^18 wei)
// ============================================================
import { connect } from 'net';
import { createHash, randomBytes } from 'crypto';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import * as fs from 'fs';
class Ed25519 {
    static p = 2n ** 255n - 19n;
    static L = 2n ** 252n + 27742317777372353535851937790883648493n;
    static d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
    static SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
    static Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
    static Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
    static G_EXT = [
        Ed25519.Gx, Ed25519.Gy, 1n, (Ed25519.Gx * Ed25519.Gy) % Ed25519.p,
    ];
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
        return [this.mod(E * F, P), this.mod(G * H, P), this.mod(F * G, P), this.mod(E * H, P)];
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
        return [this.mod(E * F, P), this.mod(G * H, P), this.mod(F * G, P), this.mod(E * H, P)];
    }
    static extToAffine(pt) {
        const [X, Y, Z] = pt;
        if (Z === 0n)
            return [0n, 1n];
        const zi = this.modInv(Z, this.p);
        return [this.mod(X * zi, this.p), this.mod(Y * zi, this.p)];
    }
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
        if (this.mod(yc - xc, P) !== this.mod(1n + ((this.d * ((xc * yc) % P)) % P), P))
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
}
// ============================================================
// 定数 & Wei変換
// ============================================================
const DELIMITER = '\nLINE_BREAK\n';
const BTR_ADDRESS = '0x0000000000000000';
const WEI_PER_BTR = 1000000000000000000n; // 10^18
const CONFIG = {
    SEED_PORT: 5000,
    CDN_SEEDS_URL: 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/fullserver/seeds.json',
    CHAIN_FILE: './chain.json',
    ACCOUNTS_FILE: './accounts.json',
    TOKENS_FILE: './tokens.json',
    // ジェネシス設定
    TOTAL_SUPPLY: (5000000000n * WEI_PER_BTR).toString(), // 5B BTR in Wei
    BLOCK_TIME: 180,
    BLOCK_REWARD_MIN: (20n * WEI_PER_BTR).toString(), // 20 BTR
    BLOCK_REWARD_MAX: (70n * WEI_PER_BTR).toString(), // 70 BTR
    GAS_FEE: (1n * WEI_PER_BTR).toString(), // 1 BTR
    TOKEN_CREATION_FEE: (500n * WEI_PER_BTR).toString(), // 500 BTR
    TOKEN_RENAME_FEE: (500n * WEI_PER_BTR).toString(), // 500 BTR
    TIMESTAMP_TOLERANCE: 10 * 60 * 1000,
    MAX_BLOCK_SIZE: 3 * 1024 * 1024,
    // === LWMA難易度調整 ===
    DIFFICULTY_WINDOW: 20, // 過去20ブロックで調整
    INITIAL_DIFFICULTY: 6, // 初期難易度
    MIN_DIFFICULTY: 5, // 最低難易度
    LWMA_CLAMP_MIN: 30, // 外れ値フィルタ下限 (秒)
    LWMA_CLAMP_MAX: 900, // 外れ値フィルタ上限 (15分)
    LWMA_DAMPING: 3, // ダンピング係数 (変化量を1/3に)
    DIFFICULTY_ADJUST_START: 20, // 調整開始ブロック高さ
    ROOT_PUBLIC_KEY: '04920517f44339fed12ebbc8f2c0ae93a0c2bfa4a9ef4bfee1c6f12b452eab70',
};
// ============================================================
// Wei演算ヘルパー
// ============================================================
function addWei(a, b) {
    return (BigInt(a || "0") + BigInt(b || "0")).toString();
}
function subWei(a, b) {
    return (BigInt(a || "0") - BigInt(b || "0")).toString();
}
function compareWei(a, b) {
    const diff = BigInt(a || "0") - BigInt(b || "0");
    if (diff > 0n)
        return 1;
    if (diff < 0n)
        return -1;
    return 0;
}
function mulWei(a, b) {
    return (BigInt(a || "0") * BigInt(b || "0")).toString();
}
function divWei(a, b) {
    if (BigInt(b || "0") === 0n)
        return "0";
    return (BigInt(a || "0") / BigInt(b || "0")).toString();
}
function btrToWei(btr) {
    return (BigInt(Math.floor(btr)) * WEI_PER_BTR).toString();
}
function weiToBtrDisplay(wei) {
    try {
        const w = BigInt(wei);
        const whole = w / WEI_PER_BTR;
        const frac = w % WEI_PER_BTR;
        const fracStr = frac.toString().padStart(18, '0').replace(/0+$/, '');
        return fracStr ? `${whole}.${fracStr}` : whole.toString();
    }
    catch {
        return "0";
    }
}
// ============================================================
// ヘルパー
// ============================================================
function sha256(data) {
    return createHash('sha256').update(data).digest('hex');
}
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
function canonicalJSON(obj) {
    if (typeof obj !== 'object' || obj === null)
        return JSON.stringify(obj);
    if (Array.isArray(obj))
        return '[' + obj.map(canonicalJSON).join(',') + ']';
    const record = obj;
    const keys = Object.keys(record).sort();
    const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalJSON(record[k])}`);
    return '{' + pairs.join(',') + '}';
}
function log(category, message) {
    const time = new Date().toISOString().slice(11, 19);
    console.log(`[${time}][${category}] ${message}`);
}
function computeBlockHash(block) {
    return sha256(block.previousHash +
        block.timestamp +
        block.nonce +
        block.difficulty +
        block.miner +
        block.reward +
        JSON.stringify(block.transactions));
}
// ============================================================
// 状態管理
// ============================================================
const chain = [];
const accounts = new Map();
const tokens = new Map();
const ammPools = new Map();
const pendingTxs = [];
let commonRandom = '';
let totalMined = "0"; // Wei文字列
let currentDifficulty = CONFIG.INITIAL_DIFFICULTY;
// ============================================================
// アカウント管理
// ============================================================
function getAccount(address) {
    if (!accounts.has(address)) {
        accounts.set(address, {
            address,
            balance: "0",
            nonce: 0,
            tokens: {},
        });
    }
    return accounts.get(address);
}
function getTokenBalance(address, tokenAddress) {
    const account = getAccount(address);
    return account.tokens[tokenAddress] || "0";
}
// ============================================================
// ジェネシスブロック
// ============================================================
function createGenesisBlock() {
    const block = {
        height: 0,
        previousHash: '0x' + '0'.repeat(64),
        timestamp: Date.now(),
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
async function verifyTransaction(tx) {
    // 1. 公開鍵 → アドレス検証
    const expectedAddress = '0x' + sha256(tx.publicKey).slice(0, 40);
    if (expectedAddress !== tx.from) {
        return { valid: false, error: '公開鍵とアドレスが不一致' };
    }
    // 2. 署名検証
    const { signature, ...rest } = tx;
    const message = canonicalJSON(rest);
    try {
        const valid = await Ed25519.verify(hexToBytes(signature), new TextEncoder().encode(message), hexToBytes(tx.publicKey));
        if (!valid)
            return { valid: false, error: `署名が無効 (from=${tx.from.slice(0, 10)}..., pubkey=${tx.publicKey.slice(0, 16)}..., sig=${signature.slice(0, 16)}...)` };
    }
    catch (e) {
        const detail = e instanceof Error ? e.message : String(e);
        return { valid: false, error: `署名検証エラー: ${detail} (pubkey=${tx.publicKey.slice(0, 16)}..., sig長=${signature.length})` };
    }
    // 3. タイムスタンプ
    if (Math.abs(Date.now() - tx.timestamp) > CONFIG.TIMESTAMP_TOLERANCE) {
        return { valid: false, error: 'タイムスタンプが範囲外' };
    }
    // 4. nonce
    const account = getAccount(tx.from);
    if (tx.nonce !== account.nonce) {
        return { valid: false, error: `nonce不一致 (期待: ${account.nonce}, 受信: ${tx.nonce})` };
    }
    // 5. 手数料 (Wei文字列で比較)
    if (tx.fee !== CONFIG.GAS_FEE) {
        return { valid: false, error: 'ガス代が不正' };
    }
    // 6. 残高チェック (ガス代分)
    if (compareWei(account.balance, tx.fee) < 0) {
        return { valid: false, error: 'ガス代の残高不足' };
    }
    // 7. type別チェック
    switch (tx.type) {
        case 'transfer': {
            if (!tx.to || !tx.amount || compareWei(tx.amount, "0") <= 0) {
                return { valid: false, error: 'transfer: 宛先または金額が不正' };
            }
            if (tx.token === BTR_ADDRESS) {
                if (compareWei(account.balance, addWei(tx.amount, tx.fee)) < 0) {
                    return { valid: false, error: 'BTR残高不足' };
                }
            }
            break;
        }
        case 'token_transfer': {
            if (!tx.to || !tx.amount || compareWei(tx.amount, "0") <= 0) {
                return { valid: false, error: 'token_transfer: 宛先または金額が不正' };
            }
            const tokenBal = getTokenBalance(tx.from, tx.token);
            if (compareWei(tokenBal, tx.amount) < 0) {
                return { valid: false, error: 'トークン残高不足' };
            }
            break;
        }
        case 'create_token': {
            if (!tx.data?.name || !tx.data?.symbol || !tx.data?.totalSupply || compareWei(tx.data.totalSupply, "0") <= 0) {
                return { valid: false, error: 'create_token: データが不正' };
            }
            if (compareWei(account.balance, addWei(CONFIG.TOKEN_CREATION_FEE, tx.fee)) < 0) {
                return { valid: false, error: 'トークン作成費の残高不足' };
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
                if (compareWei(account.balance, addWei(tx.data.amountIn, tx.fee)) < 0) {
                    return { valid: false, error: 'swap: BTR残高不足' };
                }
            }
            else {
                const tokenBal = getTokenBalance(tx.from, tx.data.tokenIn);
                if (compareWei(tokenBal, tx.data.amountIn) < 0) {
                    return { valid: false, error: 'swap: トークン残高不足' };
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
            if (compareWei(account.balance, addWei(CONFIG.TOKEN_RENAME_FEE, tx.fee)) < 0) {
                return { valid: false, error: 'トークン名変更費の残高不足' };
            }
            const token = tokens.get(tx.token);
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
function applyTransaction(tx, minerAddress) {
    const sender = getAccount(tx.from);
    const miner = getAccount(minerAddress);
    const isSelfMining = (tx.from === minerAddress);
    // ガス代
    if (!isSelfMining) {
        sender.balance = subWei(sender.balance, tx.fee);
        miner.balance = addWei(miner.balance, tx.fee);
    }
    sender.nonce++;
    switch (tx.type) {
        case 'transfer': {
            const receiver = getAccount(tx.to);
            if (tx.token === BTR_ADDRESS) {
                sender.balance = subWei(sender.balance, tx.amount);
                receiver.balance = addWei(receiver.balance, tx.amount);
            }
            break;
        }
        case 'token_transfer': {
            const receiver = getAccount(tx.to);
            const senderBal = sender.tokens[tx.token] || "0";
            sender.tokens[tx.token] = subWei(senderBal, tx.amount);
            const receiverBal = receiver.tokens[tx.token] || "0";
            receiver.tokens[tx.token] = addWei(receiverBal, tx.amount);
            break;
        }
        case 'create_token': {
            sender.balance = subWei(sender.balance, CONFIG.TOKEN_CREATION_FEE);
            if (!isSelfMining) {
                miner.balance = addWei(miner.balance, CONFIG.TOKEN_CREATION_FEE);
            }
            const tokenAddress = '0x' + sha256(tx.signature + tx.timestamp).slice(0, 16);
            const poolRatio = tx.data.poolRatio || 0;
            const totalSupply = tx.data.totalSupply;
            const tokenInfo = {
                address: tokenAddress,
                symbol: tx.data.symbol,
                name: tx.data.name,
                creator: tx.publicKey,
                createdAt: tx.timestamp,
                totalSupply,
                distributed: totalSupply,
                poolRatio,
                distribution: tx.data.distribution || 'creator',
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
                    btrReserve: CONFIG.TOKEN_CREATION_FEE, // 作成費がプールの初期BTRリザーブ
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
            const token = tokens.get(tx.token);
            if (token) {
                token.name = tx.data.newName;
            }
            break;
        }
    }
}
// ============================================================
// AMM (BigInt版)
// ============================================================
function getAMMRate(tokenAddress) {
    const pool = ammPools.get(tokenAddress);
    if (!pool || compareWei(pool.tokenReserve, "0") <= 0)
        return "0";
    // rate = btrReserve * 97 / (tokenReserve * 100) — 3%手数料込み
    // 精度保持のため WEI_PER_BTR をかけてから割る
    const rate = (BigInt(pool.btrReserve) * 97n * WEI_PER_BTR) / (BigInt(pool.tokenReserve) * 100n);
    return rate.toString();
}
function getFluctuatedRate(tokenAddress, minute) {
    const baseRate = getAMMRate(tokenAddress);
    if (baseRate === "0" || !commonRandom)
        return baseRate;
    const seed = sha256(commonRandom + tokenAddress + minute);
    const fluctuation = parseInt(seed.slice(0, 8), 16);
    const change = (fluctuation % 3000 - 1500); // -1500 ~ +1500
    // rate = base * (10000 + change) / 10000
    const base = BigInt(baseRate);
    const result = (base * BigInt(10000 + change)) / 10000n;
    return result.toString();
}
const FEE_NUMERATOR = 3n;
const FEE_DENOMINATOR = 100n;
function executeSwap(tx) {
    const tokenIn = tx.data.tokenIn;
    const tokenOut = tx.data.tokenOut;
    const amountIn = BigInt(tx.data.amountIn);
    const sender = getAccount(tx.from);
    if (tokenIn === BTR_ADDRESS) {
        // BTR → Token
        const pool = ammPools.get(tokenOut);
        if (!pool)
            return;
        if (compareWei(sender.balance, amountIn.toString()) < 0)
            return;
        const fee = amountIn * FEE_NUMERATOR / FEE_DENOMINATOR;
        const amountInAfterFee = amountIn - fee;
        sender.balance = subWei(sender.balance, amountIn.toString());
        const amountOut = (amountInAfterFee * BigInt(pool.tokenReserve)) / (BigInt(pool.btrReserve) + amountInAfterFee);
        pool.btrReserve = addWei(pool.btrReserve, amountIn.toString());
        pool.tokenReserve = subWei(pool.tokenReserve, amountOut.toString());
        sender.tokens[tokenOut] = addWei(sender.tokens[tokenOut] || "0", amountOut.toString());
    }
    else if (tokenOut === BTR_ADDRESS) {
        // Token → BTR
        const pool = ammPools.get(tokenIn);
        if (!pool)
            return;
        const senderBal = sender.tokens[tokenIn] || "0";
        if (compareWei(senderBal, amountIn.toString()) < 0)
            return;
        const fee = amountIn * FEE_NUMERATOR / FEE_DENOMINATOR;
        const amountInAfterFee = amountIn - fee;
        sender.tokens[tokenIn] = subWei(senderBal, amountIn.toString());
        const amountOut = (amountInAfterFee * BigInt(pool.btrReserve)) / (BigInt(pool.tokenReserve) + amountInAfterFee);
        pool.tokenReserve = addWei(pool.tokenReserve, amountIn.toString());
        pool.btrReserve = subWei(pool.btrReserve, amountOut.toString());
        sender.balance = addWei(sender.balance, amountOut.toString());
    }
    else {
        // Token → Token (TokenA → BTR → TokenB)
        const poolA = ammPools.get(tokenIn);
        const poolB = ammPools.get(tokenOut);
        if (!poolA || !poolB)
            return;
        const senderBal = sender.tokens[tokenIn] || "0";
        if (compareWei(senderBal, amountIn.toString()) < 0)
            return;
        const feeA = amountIn * FEE_NUMERATOR / FEE_DENOMINATOR;
        const amountInAfterFee = amountIn - feeA;
        sender.tokens[tokenIn] = subWei(senderBal, amountIn.toString());
        // TokenA → BTR
        const btrAmount = (amountInAfterFee * BigInt(poolA.btrReserve)) / (BigInt(poolA.tokenReserve) + amountInAfterFee);
        poolA.tokenReserve = addWei(poolA.tokenReserve, amountIn.toString());
        poolA.btrReserve = subWei(poolA.btrReserve, btrAmount.toString());
        // BTR → TokenB (2回目手数料)
        const feeB = btrAmount * FEE_NUMERATOR / FEE_DENOMINATOR;
        const btrAmountAfterFee = btrAmount - feeB;
        const amountOut = (btrAmountAfterFee * BigInt(poolB.tokenReserve)) / (BigInt(poolB.btrReserve) + btrAmountAfterFee);
        poolB.btrReserve = addWei(poolB.btrReserve, btrAmount.toString());
        poolB.tokenReserve = subWei(poolB.tokenReserve, amountOut.toString());
        sender.tokens[tokenOut] = addWei(sender.tokens[tokenOut] || "0", amountOut.toString());
    }
}
// ============================================================
// ブロック検証
// ============================================================
function verifyBlock(block) {
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
    const expectedHash = computeBlockHash(block);
    if (block.hash !== expectedHash) {
        return { valid: false, error: `ブロックハッシュ不一致 (計算=${expectedHash.slice(0, 16)}..., ブロック=${block.hash.slice(0, 16)}...)` };
    }
    if (!block.hash.startsWith('0'.repeat(block.difficulty))) {
        return { valid: false, error: `PoW条件を満たしていない (先頭0が${block.difficulty}個必要)` };
    }
    if (chain.length > 0) {
        const prev = chain[chain.length - 1];
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
    // タイムスタンプチェック（未来のブロックを拒否）
    if (block.timestamp > Date.now() + 30000) {
        return { valid: false, error: 'タイムスタンプが未来すぎる' };
    }
    const size = Buffer.byteLength(JSON.stringify(block.transactions));
    if (size > CONFIG.MAX_BLOCK_SIZE) {
        return { valid: false, error: `ブロックサイズ超過 (${size} > ${CONFIG.MAX_BLOCK_SIZE})` };
    }
    // 報酬チェック (Wei文字列比較)
    if (compareWei(block.reward, CONFIG.BLOCK_REWARD_MIN) < 0 || compareWei(block.reward, CONFIG.BLOCK_REWARD_MAX) > 0) {
        return { valid: false, error: `報酬が範囲外 (${block.reward.slice(0, 20)}...)` };
    }
    return { valid: true };
}
// ============================================================
// ブロック適用
// ============================================================
function applyBlock(block) {
    // マイニング報酬
    if (block.height > 0 && compareWei(totalMined, CONFIG.TOTAL_SUPPLY) < 0) {
        const miner = getAccount(block.miner);
        const remaining = subWei(CONFIG.TOTAL_SUPPLY, totalMined);
        const reward = compareWei(block.reward, remaining) <= 0 ? block.reward : remaining;
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
            const miner = getAccount(block.miner);
            const remaining = subWei(token.totalSupply, token.distributed);
            const tokenReward = compareWei(MINING_TOKEN_REWARD, remaining) <= 0 ? MINING_TOKEN_REWARD : remaining;
            miner.tokens[token.address] = addWei(miner.tokens[token.address] || "0", tokenReward);
            token.distributed = addWei(token.distributed, tokenReward);
        }
    }
    chain.push(block);
    // ブロックファイル保存 (rebuilding中はスキップ、後でsaveStateがまとめて保存)
    if (!isRebuilding) {
        try {
            const filename = `./chain/${block.height.toString().padStart(64, '0')}.json`;
            writeFileSync(filename, JSON.stringify(block));
        }
        catch (e) {
            log('Save', `ブロック保存失敗: ${e}`);
        }
    }
    adjustDifficulty();
    // pending から適用済みTxを除去
    const txSigs = new Set(block.transactions.map(tx => tx.signature));
    const remaining = pendingTxs.filter(tx => !txSigs.has(tx.signature));
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
function calculateDifficultyFromChain(c) {
    // 20ブロック未満の場合は初期難易度
    if (c.length < CONFIG.DIFFICULTY_ADJUST_START + 1) {
        return CONFIG.INITIAL_DIFFICULTY;
    }
    // ジェネシス(height=0)を除外した範囲でwindowを計算
    const nonGenesis = c.slice(1); // height 1以降
    const window = Math.min(CONFIG.DIFFICULTY_WINDOW, nonGenesis.length - 1);
    if (window < 2)
        return CONFIG.INITIAL_DIFFICULTY;
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
    let newDiff;
    if (ratio < 0.85) {
        // 速すぎ → 難易度UP (ダンピング適用)
        const change = Math.ceil((1 / ratio - 1) / CONFIG.LWMA_DAMPING);
        newDiff = currentDiff + Math.max(1, change);
    }
    else if (ratio > 1.15) {
        // 遅すぎ → 難易度DOWN (ダンピング適用)
        const change = Math.ceil((ratio - 1) / CONFIG.LWMA_DAMPING);
        newDiff = currentDiff - Math.max(1, change);
    }
    else {
        newDiff = currentDiff;
    }
    // 最低難易度制限
    newDiff = Math.max(CONFIG.MIN_DIFFICULTY, newDiff);
    // 1ブロックで最大+1しか上がらない（急激な上昇防止）
    newDiff = Math.min(currentDiff + 1, newDiff);
    return newDiff;
}
function adjustDifficulty() {
    const newDiff = calculateDifficultyFromChain(chain);
    const oldDifficulty = currentDifficulty;
    currentDifficulty = newDiff;
    // rebuildState中は通知しない（大量送信防止）
    if (isRebuilding)
        return;
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
function calculateReward(height) {
    if (!commonRandom)
        return (45n * WEI_PER_BTR).toString(); // 45 BTR default
    if (compareWei(totalMined, CONFIG.TOTAL_SUPPLY) >= 0)
        return "0";
    const seed = sha256(commonRandom + 'BTR_REWARD' + height);
    const value = parseInt(seed.slice(0, 8), 16);
    const range = 70 - 20 + 1;
    const rewardBtr = 20 + (value % range);
    const rewardWei = (BigInt(rewardBtr) * WEI_PER_BTR).toString();
    const remaining = subWei(CONFIG.TOTAL_SUPPLY, totalMined);
    return compareWei(rewardWei, remaining) <= 0 ? rewardWei : remaining;
}
// ============================================================
// フォーク選択
// ============================================================
function calculateChainWork(c) {
    return c.reduce((sum, b) => sum + (2n ** BigInt(b.difficulty)), 0n);
}
function selectChain(otherChain) {
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
let isRebuilding = false;
function rebuildState(newChain) {
    chain.length = 0;
    accounts.clear();
    tokens.clear();
    ammPools.clear();
    totalMined = "0";
    currentDifficulty = CONFIG.INITIAL_DIFFICULTY;
    isRebuilding = true;
    for (const block of newChain) {
        applyBlock(block);
    }
    isRebuilding = false;
}
// ============================================================
// 永続化
// ============================================================
function saveState() {
    try {
        if (!existsSync('./chain'))
            fs.mkdirSync('./chain', { recursive: true });
        if (!existsSync('./users'))
            fs.mkdirSync('./users', { recursive: true });
        if (!existsSync('./tokens'))
            fs.mkdirSync('./tokens', { recursive: true });
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
    }
    catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log('Save', `保存失敗: ${msg}`);
    }
}
function loadState() {
    try {
        if (!existsSync('./chain'))
            fs.mkdirSync('./chain', { recursive: true });
        if (!existsSync('./users'))
            fs.mkdirSync('./users', { recursive: true });
        if (!existsSync('./tokens'))
            fs.mkdirSync('./tokens', { recursive: true });
        let chainLength = 0;
        if (existsSync('./state_meta.json')) {
            const meta = JSON.parse(readFileSync('./state_meta.json', 'utf-8'));
            chainLength = meta.chainLength || 0;
        }
        if (chainLength > 0) {
            const blocks = [];
            for (let height = 0; height < chainLength; height++) {
                const filename = `./chain/${height.toString().padStart(64, '0')}.json`;
                if (existsSync(filename)) {
                    const block = JSON.parse(readFileSync(filename, 'utf-8'));
                    blocks.push(block);
                }
                else {
                    log('Load', `⚠ ブロックファイル欠落: height ${height}`);
                }
            }
            if (blocks.length > 0) {
                rebuildState(blocks);
                log('Load', `チェーン読み込み: ${chain.length}ブロック`);
            }
            else {
                const genesis = createGenesisBlock();
                chain.push(genesis);
                log('Load', 'ジェネシスブロック作成');
            }
        }
        else {
            if (existsSync(CONFIG.CHAIN_FILE)) {
                log('Load', '旧形式検出: 移行不可（BigInt版は互換性なし）');
            }
            const genesis = createGenesisBlock();
            chain.push(genesis);
            log('Load', 'ジェネシスブロック作成 (BigInt版)');
        }
    }
    catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log('Load', `読み込み失敗: ${msg}`);
        const genesis = createGenesisBlock();
        chain.push(genesis);
    }
}
// ============================================================
// チェーン同期
// ============================================================
let syncBuffer = [];
let syncExpectedFrom = 0;
let syncTimer = null;
let isSyncing = false;
function startSyncTimeout() {
    if (syncTimer)
        clearTimeout(syncTimer);
    syncTimer = setTimeout(() => {
        if (isSyncing) {
            log('Sync', 'タイムアウト — フォールバック');
            isSyncing = false;
            syncBuffer = [];
            sendToSeed({ type: 'request_chain', data: { fromHeight: chain.length } });
            syncTimer = setTimeout(() => {
                if (chain.length <= 1)
                    log('Sync', '同期失敗、ジェネシスから開始');
                syncTimer = null;
            }, 15000);
        }
    }, 10000);
}
function finishSync() {
    isSyncing = false;
    if (syncTimer) {
        clearTimeout(syncTimer);
        syncTimer = null;
    }
    // チェーンからLWMAで正しい難易度を再計算
    currentDifficulty = calculateDifficultyFromChain(chain);
    log('Sync', `難易度をチェーンから再計算: diff=${currentDifficulty}`);
    saveState();
    try {
        const meta = { chainLength: chain.length, accountCount: accounts.size, tokenCount: tokens.size, lastSaved: Date.now() };
        writeFileSync('./state_meta.json', JSON.stringify(meta, null, 2));
    }
    catch (e) {
        log('Save', `メタデータ保存失敗: ${e}`);
    }
    sendToSeed({ type: 'height', data: { height: chain.length, difficulty: currentDifficulty } });
    log('Sync', `同期完了: ${chain.length}ブロック, 難易度=${currentDifficulty}`);
}
// ============================================================
// シードノード接続（seeds.json ベース、優先度順）
// ============================================================
let seedSocket = null;
let seedBuffer = '';
let currentSeedHost = '';
let lastSeedsHash = '';
function loadSeeds() {
    try {
        if (existsSync('./seeds.json')) {
            const data = JSON.parse(readFileSync('./seeds.json', 'utf-8'));
            const seeds = data.seeds || [];
            return seeds.sort((a, b) => a.priority - b.priority);
        }
    }
    catch (e) {
        log('Net', `seeds.json 読み込み失敗: ${e}`);
    }
    // フォールバック
    return [{ host: 'mail.shudo-physics.com', priority: 1, publicKey: '' }];
}
async function checkSeedsUpdate() {
    try {
        log('Net', 'CDN seeds.json チェック中...');
        const res = await fetch(CONFIG.CDN_SEEDS_URL);
        if (!res.ok)
            return;
        const text = await res.text();
        const hash = sha256(text);
        if (!lastSeedsHash) {
            lastSeedsHash = hash;
            return;
        }
        if (hash !== lastSeedsHash) {
            log('Net', 'seeds.json 更新検出、保存して再接続');
            writeFileSync('./seeds.json', text);
            lastSeedsHash = hash;
        }
    }
    catch {
        // ネットワーク不通なら無視
    }
}
function connectToSeed(seedIndex = 0) {
    const seeds = loadSeeds();
    if (seedIndex >= seeds.length) {
        log('Net', '全シードノード接続失敗、5秒後にリトライ');
        setTimeout(() => connectToSeed(0), 5000);
        return;
    }
    const seed = seeds[seedIndex];
    currentSeedHost = seed.host;
    log('Net', `シードノードに接続中: ${seed.host}:${CONFIG.SEED_PORT} (優先度${seed.priority})`);
    seedSocket = connect(CONFIG.SEED_PORT, seed.host, () => {
        log('Net', `接続成功: ${seed.host}`);
        sendToSeed({
            type: 'register',
            data: { chainHeight: chain.length, difficulty: currentDifficulty }
        });
        isSyncing = true;
        startSyncTimeout();
    });
    seedSocket.on('data', (data) => {
        seedBuffer += data.toString();
        const parts = seedBuffer.split(DELIMITER);
        seedBuffer = parts.pop() || '';
        for (const part of parts) {
            if (!part.trim())
                continue;
            try {
                const packet = JSON.parse(part);
                handlePacket(packet);
            }
            catch { }
        }
    });
    seedSocket.on('close', () => {
        log('Net', `シードノード切断 (${currentSeedHost})`);
        seedSocket = null;
        // 切断時にCDNチェック
        checkSeedsUpdate().then(() => {
            log('Net', '3秒後に再接続...');
            setTimeout(() => connectToSeed(0), 3000);
        });
    });
    seedSocket.on('error', (err) => {
        log('Net', `接続エラー (${seed.host}): ${err.message}`);
        seedSocket = null;
        // 次のシードを試す
        connectToSeed(seedIndex + 1);
    });
}
function sendToSeed(packet) {
    if (seedSocket && !seedSocket.destroyed) {
        seedSocket.write(JSON.stringify(packet) + DELIMITER);
    }
}
// ============================================================
// パケットハンドリング
// ============================================================
async function handlePacket(packet) {
    // 同期中はクライアント向けリクエストとブロードキャストを拒否（ノード間同期通信は通す）
    const blockedDuringSyncWithResponse = new Set([
        'get_balance', 'get_height', 'get_block_template', 'get_chain',
        'get_token', 'get_tokens_list', 'get_rate', 'get_mempool',
        'get_recent_transactions', 'get_block', 'tx', 'admin_status'
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
            const block = blockOnly;
            const result = verifyBlock(block);
            if (result.valid) {
                applyBlock(block);
                log('Block', `ブロック適用: #${block.height} by ${block.miner.slice(0, 10)}... (${block.transactions.length}tx)`);
                saveState();
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
            }
            else {
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
            const clientId = packet.data?.clientId;
            const { clientId: _cid, ...txOnly } = packet.data;
            const tx = txOnly;
            const result = await verifyTransaction(tx);
            if (result.valid) {
                pendingTxs.push(tx);
                log('Tx', `受付: ${tx.type} from ${tx.from.slice(0, 10)}...`);
                sendToSeed({ type: 'tx_broadcast', data: tx });
                if (clientId) {
                    sendToSeed({ type: 'tx_result', data: { clientId, success: true, txType: tx.type } });
                }
            }
            else {
                log('Tx', `拒否: ${result.error}`);
                if (clientId) {
                    sendToSeed({ type: 'tx_result', data: { clientId, success: false, error: result.error } });
                }
            }
            break;
        }
        case 'tx_broadcast': {
            const tx = packet.data;
            const result = await verifyTransaction(tx);
            if (result.valid) {
                const exists = pendingTxs.some(p => p.signature === tx.signature);
                if (!exists)
                    pendingTxs.push(tx);
            }
            break;
        }
        // --- クライアント照会 ---
        case 'get_balance': {
            const clientId = packet.data?.clientId;
            const address = packet.data?.address;
            const account = getAccount(address);
            const adminRequest = packet.data?.adminRequest || false;
            if (adminRequest) {
                sendToSeed({
                    type: 'admin_account',
                    data: { clientId, found: true, account: { address: account.address, balance: account.balance, nonce: account.nonce, tokens: account.tokens } }
                });
            }
            else {
                sendToSeed({
                    type: 'balance',
                    data: { clientId, address, balance: account.balance, nonce: account.nonce, tokens: account.tokens }
                });
            }
            break;
        }
        case 'get_height': {
            const clientId = packet.data?.clientId;
            const latestHash = chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64);
            sendToSeed({
                type: 'height',
                data: { clientId, height: chain.length, difficulty: currentDifficulty, latestHash }
            });
            break;
        }
        case 'get_block_template': {
            const clientId = packet.data?.clientId;
            const miner = packet.data?.miner || '';
            const latestHash = chain.length > 0 ? chain[chain.length - 1].hash : '0'.repeat(64);
            const reward = calculateReward(chain.length);
            sendToSeed({
                type: 'block_template',
                data: {
                    clientId, height: chain.length, previousHash: latestHash,
                    difficulty: currentDifficulty, reward, transactions: pendingTxs, miner,
                }
            });
            break;
        }
        case 'get_chain': {
            const clientId = packet.data?.clientId;
            let from = packet.data?.from || 0;
            let to = packet.data?.to || chain.length;
            const isAdmin = packet.data?.admin || false;
            if (from < 0) {
                from = Math.max(0, chain.length + from);
                to = chain.length;
            }
            const chunk = chain.slice(from, to);
            if (isAdmin) {
                sendToSeed({ type: 'admin_blocks', data: { clientId, blocks: chunk } });
            }
            else {
                sendToSeed({ type: 'chain_chunk', data: { clientId, from, to, blocks: chunk } });
            }
            break;
        }
        case 'get_token': {
            const clientId = packet.data?.clientId;
            const tokenAddress = packet.data?.address;
            const token = tokens.get(tokenAddress);
            sendToSeed({ type: 'token_info', data: { clientId, token: token || null } });
            break;
        }
        case 'get_tokens_list': {
            const clientId = packet.data?.clientId;
            const list = Array.from(tokens.values()).map(t => ({
                address: t.address, symbol: t.symbol, name: t.name, totalSupply: t.totalSupply
            }));
            sendToSeed({ type: 'tokens_list', data: { clientId, tokens: list } });
            break;
        }
        case 'get_rate': {
            const clientId = packet.data?.clientId;
            const tokenAddress = packet.data?.address;
            const minute = Math.floor(Date.now() / 60000);
            const rate = getFluctuatedRate(tokenAddress, minute);
            sendToSeed({ type: 'rate', data: { clientId, tokenAddress, rate, minute } });
            break;
        }
        case 'get_mempool': {
            const clientId = packet.data?.clientId;
            const isAdmin = packet.data?.admin || false;
            const responseType = isAdmin ? 'admin_mempool' : 'mempool';
            sendToSeed({
                type: responseType,
                data: { clientId, count: pendingTxs.length, transactions: pendingTxs.slice(0, 50) }
            });
            break;
        }
        case 'get_recent_transactions': {
            const clientId = packet.data?.clientId;
            const limit = packet.data?.limit || 50;
            const isAdmin = packet.data?.admin || false;
            const recentTxs = [];
            for (let i = chain.length - 1; i >= 0 && recentTxs.length < limit; i--) {
                for (const tx of chain[i].transactions) {
                    if (recentTxs.length >= limit)
                        break;
                    recentTxs.push(tx);
                }
            }
            const responseType = isAdmin ? 'admin_transactions' : 'transactions';
            sendToSeed({ type: responseType, data: { clientId, transactions: recentTxs } });
            break;
        }
        case 'get_block': {
            const clientId = packet.data?.clientId;
            const height = packet.data?.height;
            if (height >= 0 && height < chain.length) {
                sendToSeed({ type: 'block', data: { clientId, block: chain[height] } });
            }
            else {
                sendToSeed({ type: 'block', data: { clientId, block: null, error: 'ブロックが見つかりません' } });
            }
            break;
        }
        // ★ admin_mint, admin_distribute, admin_clear_mempool, admin_remove_tx は削除済み
        // --- 管理者コマンド (残存: ステータス確認のみ) ---
        case 'admin_status': {
            const clientId = packet.data?.clientId;
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
        // --- 分散乱数 ---
        case 'random_request': {
            const myRandom = randomBytes(32).toString('hex');
            const commit = sha256(myRandom);
            global.__btrRandomValue = myRandom;
            sendToSeed({ type: 'random_commit', data: { hash: commit } });
            break;
        }
        case 'random_reveal_request': {
            const myRandom = global.__btrRandomValue || '';
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
            const targetNodeId = packet.data?.targetNodeId;
            const fromHeight = packet.data?.fromHeight || 0;
            if (chain.length > fromHeight) {
                const CHUNK_SIZE = 50;
                const totalChunks = Math.ceil((chain.length - fromHeight) / CHUNK_SIZE);
                let chunkIndex = 0;
                for (let i = fromHeight; i < chain.length; i += CHUNK_SIZE) {
                    chunkIndex++;
                    const chunk = chain.slice(i, Math.min(i + CHUNK_SIZE, chain.length));
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
            const blocks = packet.data?.blocks;
            if (!blocks || blocks.length === 0)
                break;
            const chunkIndex = packet.data?.chunkIndex || 1;
            const totalChunks = packet.data?.totalChunks || 1;
            const totalHeight = packet.data?.totalHeight || 0;
            log('Sync', `チャンク受信: ${chunkIndex}/${totalChunks} (${blocks.length}ブロック)`);
            syncBuffer.push(...blocks);
            if (syncTimer)
                clearTimeout(syncTimer);
            startSyncTimeout();
            if (chunkIndex >= totalChunks || syncBuffer.length >= totalHeight) {
                log('Sync', `全チャンク受信完了: ${syncBuffer.length}ブロック`);
                syncBuffer.sort((a, b) => a.height - b.height);
                if (syncBuffer.length > chain.length) {
                    if (syncBuffer[0].height === 0) {
                        selectChain(syncBuffer);
                    }
                    else if (syncBuffer[0].height <= chain.length) {
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
            const blocks = packet.data?.blocks;
            if (!blocks || blocks.length === 0) {
                log('Sync', 'フォールバック応答: ブロックなし');
                finishSync();
                break;
            }
            log('Sync', `フォールバック受信: ${blocks.length}ブロック`);
            blocks.sort((a, b) => a.height - b.height);
            if (blocks.length > chain.length) {
                if (blocks[0].height === 0)
                    selectChain(blocks);
                else if (blocks[0].height <= chain.length) {
                    const merged = [...chain.slice(0, blocks[0].height), ...blocks];
                    selectChain(merged);
                }
            }
            finishSync();
            break;
        }
        case 'send_chain_direct': {
            const targetNodeId = packet.data?.targetNodeId;
            const fromHeight = packet.data?.fromHeight || 0;
            if (chain.length > fromHeight) {
                const blocks = chain.slice(fromHeight);
                sendToSeed({ type: 'chain_sync_direct', data: { targetNodeId, blocks } });
                log('Sync', `フォールバック送信: → ${targetNodeId} (${blocks.length}ブロック)`);
            }
            break;
        }
        // --- アップデート ---
        case 'update': {
            log('Update', `アップデート受信: v${packet.data?.version}`);
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
function startPeriodicTasks() {
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
        if (removed > 0)
            log('Mempool', `古いTx削除: ${removed}件`);
    }, 300000);
}
// ============================================================
// エントリーポイント
// ============================================================
function main() {
    console.log('========================================');
    console.log('  BTR (Buturi Coin) Full Node v2.1.0');
    console.log('  BigInt Edition (Wei = 10^18)');
    console.log('  LWMA Difficulty Adjustment');
    console.log('========================================');
    loadState();
    // 初回seeds.jsonハッシュ記録
    try {
        if (existsSync('./seeds.json')) {
            lastSeedsHash = sha256(readFileSync('./seeds.json', 'utf-8'));
        }
    }
    catch { }
    connectToSeed();
    startPeriodicTasks();
    const seeds = loadSeeds();
    log('Init', `フルノード起動完了 (BigInt版)`);
    log('Init', `チェーン高さ: ${chain.length}, 難易度: ${currentDifficulty}`);
    log('Init', `シードノード: ${seeds.length}件 (${seeds.map(s => s.host).join(', ')})`);
}
main();
//# sourceMappingURL=node.js.map