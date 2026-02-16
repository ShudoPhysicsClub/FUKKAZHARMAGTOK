// ============================================================
// BTR (Buturi Coin) - ランチャー
// これだけあれば全部始まる
// ============================================================
import { fork } from 'child_process';
import { connect } from 'net';
import { createHash } from 'crypto';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { Ed25519 } from './crypto.js';
// ============================================================
// ハードコード（変更不可）
// ============================================================
const ROOT_KEY = '04920517f44339fed12ebbc8f2c0ae93a0c2bfa4a9ef4bfee1c6f12b452eab70'; // hex 64文字
const CDN_URL = 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/fullserver/seeds.json';
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
    return createHash('sha256').update(data).digest('hex');
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
    if (existsSync('./seeds.json')) {
        try {
            const cached = JSON.parse(readFileSync('./seeds.json', 'utf-8'));
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
        const valid = await Ed25519.verify(hexToBytes(signature), new TextEncoder().encode(msg), hexToBytes(ROOT_KEY));
        if (!valid) {
            throw new Error('seeds.json 署名検証失敗');
        }
        // ローカルキャッシュ保存
        writeFileSync('./seeds.json', JSON.stringify(data, null, 2));
        log('seeds.json 取得 & 検証OK');
        return data.seeds;
    }
    catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        log(`CDN取得失敗: ${errMsg}`);
        // ローカルキャッシュがあればフォールバック
        if (existsSync('./seeds.json')) {
            const cached = JSON.parse(readFileSync('./seeds.json', 'utf-8'));
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
            const socket = connect(SEED_PORT, seed.host, () => {
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
// アップデート検証 ★変更箇所
// ============================================================
async function verifyUpdate(update, trustedKeys) {
    // ★ 必須フィールドチェック
    if (!update.signer || !update.signature || !update.hash || !update.code) {
        log('アップデート: 必須フィールドが不足しています');
        return false;
    }
    // ★ ROOT_KEYのみで検証（署名なしアップデートは拒否）
    if (update.signer !== ROOT_KEY) {
        log('アップデート: 署名者がROOT_KEYではありません');
        log(`アップデート: signer=${update.signer.slice(0, 16)}..., ROOT_KEY=${ROOT_KEY.slice(0, 16)}...`);
        return false;
    }
    // ハッシュ検証
    const calculatedHash = sha256(update.code);
    if (calculatedHash !== update.hash) {
        log('アップデート: ハッシュ不一致');
        log(`アップデート: 計算値=${calculatedHash.slice(0, 16)}..., 宣言値=${update.hash.slice(0, 16)}...`);
        return false;
    }
    // Ed25519署名検証（ROOT_KEYで検証）
    const valid = await Ed25519.verify(hexToBytes(update.signature), new TextEncoder().encode(update.hash), hexToBytes(ROOT_KEY));
    if (!valid) {
        log('アップデート: ROOT_KEY署名検証失敗');
        return false;
    }
    log('アップデート: ROOT_KEY署名検証成功');
    return true;
}
// ============================================================
// ノード起動・管理
// ============================================================
let nodeProcess = null;
function startNode() {
    if (!existsSync('./node.js')) {
        log('node.js が見つかりません、初回ブートを実行');
        boot();
        return;
    }
    log('node.js 起動');
    nodeProcess = fork('./node.js');
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
    if (existsSync('./trusted_keys.json')) {
        trustedKeys = JSON.parse(readFileSync('./trusted_keys.json', 'utf-8'));
    }
    if (!await verifyUpdate(update, trustedKeys)) {
        log('アップデート拒否');
        return;
    }
    log(`アップデート適用: v${update.version}`);
    writeFileSync('./node.js', update.code);
    if (nodeProcess) {
        nodeProcess.kill();
    }
}
// ============================================================
// 初回ブート ★変更箇所
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
            // ★ 無限ループしない: nodeCodeがnullでもスキップして待機モードにしない
            log('最新コードが配布されていません');
            log('シードノードに node.js を配置してください');
            log('30秒後にリトライ...');
            setTimeout(boot, 30000);
            return;
        }
        // 3. アップデート検証
        if (!await verifyUpdate(files.nodeCode, files.trustedKeys)) {
            log('最新コードの検証失敗、再試行...');
            setTimeout(boot, 10000);
            return;
        }
        // 4. ファイル書き出し
        writeFileSync('./node.js', files.nodeCode.code);
        writeFileSync('./trusted_keys.json', JSON.stringify(files.trustedKeys, null, 2));
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
if (existsSync('./node.js')) {
    log('node.js 検出、起動');
    startNode();
}
else {
    log('node.js 未検出、初回ブート');
    boot();
}
//# sourceMappingURL=index.js.map