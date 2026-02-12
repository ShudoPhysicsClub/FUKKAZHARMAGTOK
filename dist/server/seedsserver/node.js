// ============================================================
// BTR (Buturi Coin) - フルノード
// ランチャーからforkされて動く
// ============================================================
import { connect } from 'net';
import { createHash, randomBytes } from 'crypto';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { Ed25519 } from '../fullserver/crypto.js';
const DELIMITER = '\nLINE_BREAK\n';
const BTR_ADDRESS = '0x0000000000000000';
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
    BLOCK_TIME: 45,
    BLOCK_REWARD_MIN: 80,
    BLOCK_REWARD_MAX: 120,
    GAS_FEE: 0.5,
    TOKEN_CREATION_FEE: 10_000,
    TOKEN_RENAME_FEE: 500,
    TIMESTAMP_TOLERANCE: 10 * 60 * 1000, // ±10分
    MAX_BLOCK_SIZE: 3 * 1024 * 1024, // 3MB
    DIFFICULTY_WINDOW: 10, // 直近10ブロック
    ROOT_PUBLIC_KEY: '04920517f44339fed12ebbc8f2c0ae93a0c2bfa4a9ef4bfee1c6f12b452eab70',
};
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
        block.miner +
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
let totalMined = 0;
let currentDifficulty = 1;
// ============================================================
// アカウント管理
// ============================================================
function getAccount(address) {
    if (!accounts.has(address)) {
        accounts.set(address, {
            address,
            balance: 0,
            nonce: 0,
            tokens: {},
        });
    }
    return accounts.get(address);
}
function getTokenBalance(address, tokenAddress) {
    const account = getAccount(address);
    return account.tokens[tokenAddress] || 0;
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
            return { valid: false, error: '署名が無効' };
    }
    catch {
        return { valid: false, error: '署名検証エラー' };
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
            const tokenBal = getTokenBalance(tx.from, tx.token);
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
            break;
        }
        case 'rename_token': {
            if (!tx.data?.newName || !tx.token) {
                return { valid: false, error: 'rename_token: データが不正' };
            }
            if (account.balance < CONFIG.TOKEN_RENAME_FEE + tx.fee) {
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
    // ガス代
    sender.balance -= tx.fee;
    miner.balance += tx.fee;
    sender.nonce++;
    switch (tx.type) {
        case 'transfer': {
            const receiver = getAccount(tx.to);
            if (tx.token === BTR_ADDRESS) {
                sender.balance -= tx.amount;
                receiver.balance += tx.amount;
            }
            break;
        }
        case 'token_transfer': {
            const receiver = getAccount(tx.to);
            const senderBal = sender.tokens[tx.token] || 0;
            sender.tokens[tx.token] = senderBal - tx.amount;
            const receiverBal = receiver.tokens[tx.token] || 0;
            receiver.tokens[tx.token] = receiverBal + tx.amount;
            break;
        }
        case 'create_token': {
            sender.balance -= CONFIG.TOKEN_CREATION_FEE;
            miner.balance += CONFIG.TOKEN_CREATION_FEE;
            const tokenAddress = '0x' + randomBytes(8).toString('hex');
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
            // 配布
            const creatorAmount = totalSupply * (1 - poolRatio);
            const poolAmount = totalSupply * poolRatio;
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
            miner.balance += CONFIG.TOKEN_RENAME_FEE;
            const token = tokens.get(tx.token);
            if (token) {
                token.name = tx.data.newName;
            }
            break;
        }
    }
}
// ============================================================
// AMM
// ============================================================
function getAMMRate(tokenAddress) {
    const pool = ammPools.get(tokenAddress);
    if (!pool || pool.tokenReserve === 0)
        return 0;
    return pool.btrReserve / pool.tokenReserve;
}
function getFluctuatedRate(tokenAddress, minute) {
    const base = getAMMRate(tokenAddress);
    if (base === 0 || !commonRandom)
        return base;
    const seed = sha256(commonRandom + tokenAddress + minute);
    const fluctuation = parseInt(seed.slice(0, 8), 16);
    const change = (fluctuation % 3000 - 1500) / 10000;
    return base * (1 + change);
}
function executeSwap(tx) {
    const tokenIn = tx.data.tokenIn;
    const tokenOut = tx.data.tokenOut;
    const amountIn = tx.data.amountIn;
    const sender = getAccount(tx.from);
    if (tokenIn === BTR_ADDRESS) {
        // BTR → Token
        const pool = ammPools.get(tokenOut);
        if (!pool)
            return;
        sender.balance -= amountIn;
        const amountOut = (amountIn * pool.tokenReserve) / (pool.btrReserve + amountIn);
        pool.btrReserve += amountIn;
        pool.tokenReserve -= amountOut;
        sender.tokens[tokenOut] = (sender.tokens[tokenOut] || 0) + amountOut;
    }
    else if (tokenOut === BTR_ADDRESS) {
        // Token → BTR
        const pool = ammPools.get(tokenIn);
        if (!pool)
            return;
        const senderBal = sender.tokens[tokenIn] || 0;
        if (senderBal < amountIn)
            return;
        sender.tokens[tokenIn] = senderBal - amountIn;
        const amountOut = (amountIn * pool.btrReserve) / (pool.tokenReserve + amountIn);
        pool.tokenReserve += amountIn;
        pool.btrReserve -= amountOut;
        sender.balance += amountOut;
    }
    else {
        // Token → Token (TokenA → BTR → TokenB)
        const poolA = ammPools.get(tokenIn);
        const poolB = ammPools.get(tokenOut);
        if (!poolA || !poolB)
            return;
        const senderBal = sender.tokens[tokenIn] || 0;
        if (senderBal < amountIn)
            return;
        sender.tokens[tokenIn] = senderBal - amountIn;
        // TokenA → BTR
        const btrAmount = (amountIn * poolA.btrReserve) / (poolA.tokenReserve + amountIn);
        poolA.tokenReserve += amountIn;
        poolA.btrReserve -= btrAmount;
        // BTR → TokenB
        const amountOut = (btrAmount * poolB.tokenReserve) / (poolB.btrReserve + btrAmount);
        poolB.btrReserve += btrAmount;
        poolB.tokenReserve -= amountOut;
        sender.tokens[tokenOut] = (sender.tokens[tokenOut] || 0) + amountOut;
    }
}
// ============================================================
// ブロック検証
// ============================================================
function verifyBlock(block) {
    // 難易度チェック（ノード側の難易度を使う）
    if (block.difficulty !== currentDifficulty) {
        return { valid: false, error: `難易度不一致 (期待: ${currentDifficulty}, 受信: ${block.difficulty})` };
    }
    // ハッシュ検証
    const expectedHash = computeBlockHash(block);
    if (block.hash !== expectedHash) {
        return { valid: false, error: 'ブロックハッシュ不一致' };
    }
    // PoW検証（ノード側の難易度で）
    if (!block.hash.startsWith('0'.repeat(currentDifficulty))) {
        return { valid: false, error: 'PoW条件を満たしていない' };
    }
    // チェーン連結
    if (chain.length > 0) {
        const prev = chain[chain.length - 1];
        if (block.previousHash !== prev.hash) {
            return { valid: false, error: 'previousHash不一致' };
        }
        if (block.height !== prev.height + 1) {
            return { valid: false, error: 'height不一致' };
        }
    }
    // ブロックサイズ
    const size = Buffer.byteLength(JSON.stringify(block.transactions));
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
function applyBlock(block) {
    // マイニング報酬
    if (block.height > 0 && totalMined < CONFIG.TOTAL_SUPPLY) {
        const miner = getAccount(block.miner);
        const reward = Math.min(block.reward, CONFIG.TOTAL_SUPPLY - totalMined);
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
            const miner = getAccount(block.miner);
            const tokenReward = Math.min(100, token.totalSupply - token.distributed);
            miner.tokens[token.address] = (miner.tokens[token.address] || 0) + tokenReward;
            token.distributed += tokenReward;
        }
    }
    chain.push(block);
    // 難易度調整
    adjustDifficulty();
    // pending から適用済みTxを除去
    const txSigs = new Set(block.transactions.map(tx => tx.signature));
    const remaining = pendingTxs.filter(tx => !txSigs.has(tx.signature));
    pendingTxs.length = 0;
    pendingTxs.push(...remaining);
}
// ============================================================
// 難易度調整
// ============================================================
function adjustDifficulty() {
    if (chain.length < CONFIG.DIFFICULTY_WINDOW + 1)
        return;
    const recent = chain.slice(-CONFIG.DIFFICULTY_WINDOW);
    const totalTime = recent[recent.length - 1].timestamp - recent[0].timestamp;
    const avgTime = totalTime / (recent.length - 1);
    if (avgTime < 40000) {
        currentDifficulty++;
        log('Difficulty', `難易度UP: ${currentDifficulty} (平均 ${(avgTime / 1000).toFixed(1)}秒)`);
    }
    else if (avgTime > 50000 && currentDifficulty > 1) {
        currentDifficulty--;
        log('Difficulty', `難易度DOWN: ${currentDifficulty} (平均 ${(avgTime / 1000).toFixed(1)}秒)`);
    }
}
// ============================================================
// ブロック報酬算出（分散乱数ベース）
// ============================================================
function calculateReward(height) {
    if (!commonRandom)
        return 100;
    if (totalMined >= CONFIG.TOTAL_SUPPLY)
        return 0;
    const seed = sha256(commonRandom + 'BTR_REWARD' + height);
    const value = parseInt(seed.slice(0, 8), 16);
    const reward = CONFIG.BLOCK_REWARD_MIN + (value % (CONFIG.BLOCK_REWARD_MAX - CONFIG.BLOCK_REWARD_MIN + 1));
    return Math.min(reward, CONFIG.TOTAL_SUPPLY - totalMined);
}
// ============================================================
// フォーク選択
// ============================================================
function selectChain(otherChain) {
    if (otherChain.length <= chain.length) {
        if (otherChain.length === chain.length) {
            const myDiff = chain.reduce((sum, b) => sum + b.difficulty, 0);
            const otherDiff = otherChain.reduce((sum, b) => sum + b.difficulty, 0);
            if (otherDiff <= myDiff)
                return false;
        }
        else {
            return false;
        }
    }
    // 他チェーンが長いまたは累積難易度が高い → 巻き戻し & 適用
    log('Chain', `フォーク検出: 現在=${chain.length}, 受信=${otherChain.length}`);
    rebuildState(otherChain);
    return true;
}
function rebuildState(newChain) {
    // 全リセット
    chain.length = 0;
    accounts.clear();
    tokens.clear();
    ammPools.clear();
    totalMined = 0;
    currentDifficulty = 1;
    // 再適用
    for (const block of newChain) {
        applyBlock(block);
    }
    log('Chain', `状態再構築完了: ${chain.length}ブロック`);
}
// ============================================================
// 永続化
// ============================================================
function saveState() {
    try {
        writeFileSync(CONFIG.CHAIN_FILE, JSON.stringify(chain));
        const accountsObj = Object.fromEntries(accounts);
        writeFileSync(CONFIG.ACCOUNTS_FILE, JSON.stringify(accountsObj));
        const tokensObj = Object.fromEntries(tokens);
        writeFileSync(CONFIG.TOKENS_FILE, JSON.stringify(tokensObj));
    }
    catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        log('Save', `保存失敗: ${msg}`);
    }
}
function loadState() {
    try {
        if (existsSync(CONFIG.CHAIN_FILE)) {
            const data = JSON.parse(readFileSync(CONFIG.CHAIN_FILE, 'utf-8'));
            rebuildState(data);
            log('Load', `チェーン読み込み: ${chain.length}ブロック`);
        }
        else {
            // ジェネシスブロック
            const genesis = createGenesisBlock();
            chain.push(genesis);
            log('Load', 'ジェネシスブロック作成');
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
// シードノード接続
// ============================================================
let seedSocket = null;
let seedBuffer = '';
function connectToSeed() {
    log('Net', `シードノードに接続中: ${CONFIG.SEED_HOST}:${CONFIG.SEED_PORT}`);
    seedSocket = connect(CONFIG.SEED_PORT, CONFIG.SEED_HOST, () => {
        log('Net', '接続成功');
        // ノード登録
        sendToSeed({
            type: 'register',
            data: { chainHeight: chain.length }
        });
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
            catch {
                // パース失敗
            }
        }
    });
    seedSocket.on('close', () => {
        log('Net', 'シードノード切断、3秒後に再接続');
        seedSocket = null;
        setTimeout(connectToSeed, 3000);
    });
    seedSocket.on('error', (err) => {
        log('Net', `接続エラー: ${err.message}`);
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
    switch (packet.type) {
        // --- ハートビート ---
        case 'ping':
            sendToSeed({ type: 'pong' });
            break;
        // --- ノードリスト ---
        case 'node_list':
            log('Net', `ノードリスト受信: ${packet.data?.nodes?.length || 0}台`);
            break;
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
            // clientIdを除去してトランザクションだけにする
            const { clientId: _cid, ...txOnly } = packet.data;
            const tx = txOnly;
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
                // 重複チェック
                const exists = pendingTxs.some(p => p.signature === tx.signature);
                if (!exists) {
                    pendingTxs.push(tx);
                }
            }
            break;
        }
        // --- クライアントからの照会 ---
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
        case 'get_chain': {
            const clientId = packet.data?.clientId;
            let from = packet.data?.from || 0;
            let to = packet.data?.to || chain.length;
            const isAdmin = packet.data?.admin || false;
            // 負の値の場合は最新から取得
            if (from < 0) {
                from = Math.max(0, chain.length + from);
                to = chain.length;
            }
            const chunk = chain.slice(from, to);
            if (isAdmin) {
                sendToSeed({
                    type: 'admin_blocks',
                    data: { clientId, blocks: chunk }
                });
            }
            else {
                sendToSeed({
                    type: 'chain_chunk',
                    data: { clientId, from, to, blocks: chunk }
                });
            }
            break;
        }
        case 'get_token': {
            const clientId = packet.data?.clientId;
            const tokenAddress = packet.data?.address;
            const token = tokens.get(tokenAddress);
            sendToSeed({
                type: 'token_info',
                data: { clientId, token: token || null }
            });
            break;
        }
        case 'get_rate': {
            const clientId = packet.data?.clientId;
            const tokenAddress = packet.data?.address;
            const minute = Math.floor(Date.now() / 60000);
            const rate = getFluctuatedRate(tokenAddress, minute);
            sendToSeed({
                type: 'rate',
                data: { clientId, tokenAddress, rate, minute }
            });
            break;
        }
        // --- 管理者パネル用 ---
        case 'get_mempool': {
            const clientId = packet.data?.clientId;
            sendToSeed({
                type: 'admin_mempool',
                data: {
                    clientId,
                    count: pendingTxs.length,
                    transactions: pendingTxs.slice(0, 50) // 最初の50件
                }
            });
            break;
        }
        case 'get_recent_transactions': {
            const clientId = packet.data?.clientId;
            const limit = packet.data?.limit || 50;
            // 最新のブロックからトランザクションを収集
            const recentTxs = [];
            for (let i = chain.length - 1; i >= 0 && recentTxs.length < limit; i--) {
                const block = chain[i];
                for (const tx of block.transactions) {
                    if (recentTxs.length >= limit)
                        break;
                    recentTxs.push(tx);
                }
            }
            sendToSeed({
                type: 'admin_transactions',
                data: { clientId, transactions: recentTxs }
            });
            break;
        }
        // --- 管理者コマンド (root only) ---
        case 'admin_mint': {
            const { address, amount, clientId } = packet.data;
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
            }
            else {
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
            const myRandom = randomBytes(32).toString('hex');
            const commit = sha256(myRandom);
            // 一時保存（revealで使う）
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
        default:
            // 未知のパケットは無視
            break;
    }
}
// ============================================================
// 定期処理
// ============================================================
function startPeriodicTasks() {
    // チェーン高さを定期報告（30秒ごと）
    setInterval(() => {
        sendToSeed({ type: 'height', data: { height: chain.length } });
    }, 30000);
    // 状態保存（60秒ごと）
    setInterval(() => {
        saveState();
    }, 60000);
    // ログ（60秒ごと）
    setInterval(() => {
        log('Stats', `チェーン: ${chain.length}ブロック, アカウント: ${accounts.size}, pending: ${pendingTxs.length}, 発行済: ${totalMined.toLocaleString()} BTR`);
    }, 60000);
}
// ============================================================
// エントリーポイント
// ============================================================
function main() {
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
//# sourceMappingURL=node.js.map