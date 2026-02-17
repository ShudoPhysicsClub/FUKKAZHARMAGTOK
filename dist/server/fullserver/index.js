// ============================================================
// BTR (Buturi Coin) - ランチャー v3.0
// node.jsが落ちたら再起動するだけ
// ============================================================
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import https from 'https';
const CONFIG = {
    NODE_SCRIPT: './node.js',
    SEEDS_PATH: './seeds.json',
    SEEDS_CDN: 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/fullserver/seeds.json',
    RESTART_DELAY: 3000, // 再起動待機(ms)
    MAX_RAPID_RESTARTS: 5, // 短時間内の最大再起動回数
    RAPID_RESTART_WINDOW: 60000, // 短時間の定義(ms)
};
let childProcess = null;
let restartTimes = [];
let isShuttingDown = false;
function log(message) {
    const time = new Date().toISOString().slice(11, 19);
    console.log(`[${time}][Launcher] ${message}`);
}
// ============================================================
// seeds.json ダウンロード（初回のみ）
// ============================================================
async function ensureSeedsJson() {
    if (fs.existsSync(CONFIG.SEEDS_PATH)) {
        log('seeds.json 既存 → スキップ');
        return;
    }
    log('seeds.json 未検出 → CDNからダウンロード...');
    return new Promise((resolve) => {
        https.get(CONFIG.SEEDS_CDN, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    JSON.parse(data); // バリデーション
                    fs.writeFileSync(CONFIG.SEEDS_PATH, data);
                    log('✅ seeds.json ダウンロード完了');
                }
                catch (e) {
                    log(`❌ seeds.json パース失敗: ${e}`);
                }
                resolve();
            });
        }).on('error', (err) => {
            log(`❌ seeds.json ダウンロード失敗: ${err.message}`);
            resolve();
        });
    });
}
// ============================================================
// ノードプロセス管理
// ============================================================
function startNode() {
    if (isShuttingDown)
        return;
    const scriptPath = path.resolve(CONFIG.NODE_SCRIPT);
    if (!fs.existsSync(scriptPath)) {
        log(`❌ ${CONFIG.NODE_SCRIPT} が見つかりません`);
        log('3秒後にリトライ...');
        setTimeout(startNode, CONFIG.RESTART_DELAY);
        return;
    }
    log(`🚀 ノード起動: ${scriptPath}`);
    childProcess = spawn('node', [scriptPath], {
        stdio: 'inherit',
        env: { ...process.env },
    });
    childProcess.on('exit', (code, signal) => {
        childProcess = null;
        if (isShuttingDown) {
            log('シャットダウン完了');
            process.exit(0);
            return;
        }
        log(`⚠ ノード終了 (code=${code}, signal=${signal})`);
        // 短時間内の再起動回数チェック
        const now = Date.now();
        restartTimes.push(now);
        restartTimes = restartTimes.filter(t => now - t < CONFIG.RAPID_RESTART_WINDOW);
        if (restartTimes.length >= CONFIG.MAX_RAPID_RESTARTS) {
            log(`❌ ${CONFIG.RAPID_RESTART_WINDOW / 1000}秒以内に${CONFIG.MAX_RAPID_RESTARTS}回クラッシュ → 30秒待機`);
            restartTimes = [];
            setTimeout(startNode, 30000);
        }
        else {
            log(`${CONFIG.RESTART_DELAY / 1000}秒後に再起動... (${restartTimes.length}/${CONFIG.MAX_RAPID_RESTARTS})`);
            setTimeout(startNode, CONFIG.RESTART_DELAY);
        }
    });
    childProcess.on('error', (err) => {
        log(`❌ プロセスエラー: ${err.message}`);
        childProcess = null;
        setTimeout(startNode, CONFIG.RESTART_DELAY);
    });
}
// ============================================================
// シグナルハンドリング
// ============================================================
function setupSignalHandlers() {
    const shutdown = (signal) => {
        if (isShuttingDown)
            return;
        isShuttingDown = true;
        log(`${signal} 受信 → シャットダウン...`);
        if (childProcess) {
            childProcess.kill('SIGTERM');
            // 5秒待って強制終了
            setTimeout(() => {
                if (childProcess) {
                    log('強制終了');
                    childProcess.kill('SIGKILL');
                }
                process.exit(1);
            }, 5000);
        }
        else {
            process.exit(0);
        }
    };
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
}
// ============================================================
// メイン
// ============================================================
async function main() {
    console.log('========================================');
    console.log('  BTR Launcher v3.0');
    console.log('========================================');
    setupSignalHandlers();
    await ensureSeedsJson();
    startNode();
}
main();
//# sourceMappingURL=index.js.map