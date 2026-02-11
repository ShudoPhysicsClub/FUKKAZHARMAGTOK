"use strict";
// ============================================================
// BTR (Buturi Coin) - ランチャー
// これだけあれば全部始まる
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = require("child_process");
const net_1 = require("net");
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const crypto_2 = require("./crypto");
// ============================================================
// ハードコード（変更不可）
// ============================================================
const ROOT_KEY = '04920517f44339fed12ebbc8f2c0ae93a0c2bfa4a9ef4bfee1c6f12b452eab70'; // hex 64文字
const CDN_URL = 'https://cdn.example.com/btr/seeds.json';
const SEED_PORT = 5000;
const DELIMITER = '\nLINE_BREAK\n';
// ============================================================
// ヘルパー
// ============================================================
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
function sha256(data) {
    return (0, crypto_1.createHash)('sha256').update(data).digest('hex');
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
function log(msg) {
    const time = new Date().toISOString().slice(11, 19);
    console.log(`[${time}][Launcher] ${msg}`);
}
// ============================================================
// seeds.json 取得 & 検証
// ============================================================
async function fetchSeeds() {
    // まずローカルキャッシュを試す
    if ((0, fs_1.existsSync)('./seeds.json')) {
        try {
            const cached = JSON.parse((0, fs_1.readFileSync)('./seeds.json', 'utf-8'));
            log('seeds.json ローカルキャッシュ使用');
            return cached.seeds;
        }
        catch {
            // キャッシュ破損、CDNから取得
        }
    }
    // CDNから取得
    log(`seeds.json 取得中: ${CDN_URL}`);
    try {
        const res = await fetch(CDN_URL);
        const data = await res.json();
        // root署名検証
        const { signature, ...rest } = data;
        const msg = canonicalJSON(rest);
        const valid = await crypto_2.Ed25519.verify(hexToBytes(signature), new TextEncoder().encode(msg), hexToBytes(ROOT_KEY));
        if (!valid) {
            throw new Error('seeds.json 署名検証失敗');
        }
        // ローカルキャッシュ保存
        (0, fs_1.writeFileSync)('./seeds.json', JSON.stringify(data, null, 2));
        log('seeds.json 取得 & 検証OK');
        return data.seeds;
    }
    catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        log(`CDN取得失敗: ${errMsg}`);
        // ローカルキャッシュがあればフォールバック
        if ((0, fs_1.existsSync)('./seeds.json')) {
            const cached = JSON.parse((0, fs_1.readFileSync)('./seeds.json', 'utf-8'));
            log('seeds.json ローカルキャッシュにフォールバック');
            return cached.seeds;
        }
        throw new Error('seeds.json が取得できません');
    }
}
// ============================================================
// シードノードに接続して最新ファイル取得
// ============================================================
function fetchLatestFiles(seeds) {
    const sorted = [...seeds].sort((a, b) => a.priority - b.priority);
    return new Promise((resolve, reject) => {
        let index = 0;
        function tryNext() {
            if (index >= sorted.length) {
                reject(new Error('全シードノードに接続失敗'));
                return;
            }
            const seed = sorted[index++];
            log(`シードノードに接続中: ${seed.host}:${SEED_PORT}`);
            const socket = (0, net_1.connect)(SEED_PORT, seed.host, () => {
                log(`接続成功: ${seed.host}`);
                socket.write(JSON.stringify({ type: 'get_latest_files' }) + DELIMITER);
            });
            let buffer = '';
            socket.on('data', (chunk) => {
                buffer += chunk.toString();
                const parts = buffer.split(DELIMITER);
                buffer = parts.pop() || '';
                for (const part of parts) {
                    if (!part.trim())
                        continue;
                    try {
                        const packet = JSON.parse(part);
                        if (packet.type === 'latest_files' && packet.data) {
                            socket.destroy();
                            resolve(packet.data);
                        }
                    }
                    catch {
                        // パース失敗、次のパケットを待つ
                    }
                }
            });
            socket.on('error', (err) => {
                log(`接続失敗 (${seed.host}): ${err.message}`);
                tryNext();
            });
            socket.setTimeout(10000, () => {
                log(`タイムアウト: ${seed.host}`);
                socket.destroy();
                tryNext();
            });
        }
        tryNext();
    });
}
// ============================================================
// アップデート検証
// ============================================================
async function verifyUpdate(update, trustedKeys) {
    // 署名者がtrusted_keysにいるか、またはrootか
    const signerIsTrusted = update.signer === ROOT_KEY ||
        trustedKeys.keys.some(k => k.publicKey === update.signer);
    if (!signerIsTrusted) {
        log('アップデート: 署名者が信頼されていません');
        return false;
    }
    // ハッシュ検証
    if (sha256(update.code) !== update.hash) {
        log('アップデート: ハッシュ不一致');
        return false;
    }
    // Ed25519署名検証
    const valid = await crypto_2.Ed25519.verify(hexToBytes(update.signature), new TextEncoder().encode(update.hash), hexToBytes(update.signer));
    if (!valid) {
        log('アップデート: 署名検証失敗');
        return false;
    }
    return true;
}
// ============================================================
// ノード起動・管理
// ============================================================
let nodeProcess = null;
function startNode() {
    if (!(0, fs_1.existsSync)('./node.js')) {
        log('node.js が見つかりません、初回ブートを実行');
        boot();
        return;
    }
    log('node.js 起動');
    nodeProcess = (0, child_process_1.fork)('./node.js');
    nodeProcess.on('exit', (code) => {
        if (code === 100) {
            log('アップデート適用、再起動');
            startNode();
        }
        else {
            log(`node.js 終了 (code: ${code})、3秒後に再起動`);
            setTimeout(startNode, 3000);
        }
    });
    nodeProcess.on('error', (err) => {
        log(`node.js エラー: ${err.message}`);
        setTimeout(startNode, 3000);
    });
    // ノードプロセスからのアップデート受信
    nodeProcess.on('message', (msg) => {
        const message = msg;
        if (message.type === 'update' && message.data) {
            handleUpdate(message.data);
        }
    });
}
async function handleUpdate(update) {
    let trustedKeys = { keys: [] };
    if ((0, fs_1.existsSync)('./trusted_keys.json')) {
        trustedKeys = JSON.parse((0, fs_1.readFileSync)('./trusted_keys.json', 'utf-8'));
    }
    if (!await verifyUpdate(update, trustedKeys)) {
        log('アップデート拒否');
        return;
    }
    log(`アップデート適用: v${update.version}`);
    (0, fs_1.writeFileSync)('./node.js', update.code);
    if (nodeProcess) {
        nodeProcess.kill();
    }
}
// ============================================================
// 初回ブート
// ============================================================
async function boot() {
    log('=== 初回ブート開始 ===');
    try {
        // 1. seeds.json取得
        const seeds = await fetchSeeds();
        log(`シードノード: ${seeds.length}件`);
        // 2. シードノードから最新ファイル取得
        const files = await fetchLatestFiles(seeds);
        if (!files.nodeCode) {
            log('最新コードが配布されていません、待機...');
            setTimeout(boot, 10000);
            return;
        }
        // 3. アップデート検証
        if (!await verifyUpdate(files.nodeCode, files.trustedKeys)) {
            log('最新コードの検証失敗、再試行...');
            setTimeout(boot, 10000);
            return;
        }
        // 4. ファイル書き出し
        (0, fs_1.writeFileSync)('./node.js', files.nodeCode.code);
        (0, fs_1.writeFileSync)('./trusted_keys.json', JSON.stringify(files.trustedKeys, null, 2));
        log(`node.js 書き出し完了 (v${files.nodeCode.version})`);
        // 5. ノード起動
        startNode();
    }
    catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        log(`ブート失敗: ${errMsg}`);
        log('10秒後にリトライ...');
        setTimeout(boot, 10000);
    }
}
// ============================================================
// エントリーポイント
// ============================================================
log('========================================');
log('  BTR (Buturi Coin) Launcher');
log('========================================');
if ((0, fs_1.existsSync)('./node.js')) {
    log('node.js 検出、起動');
    startNode();
}
else {
    log('node.js 未検出、初回ブート');
    boot();
}
//# sourceMappingURL=index.js.map