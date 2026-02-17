// ============================================================
// BTR (Buturi Coin) - クライアント v2.1.0 BigInt完全対応版
// crypto.ts の Ed25519 を使用
// 全金額は Wei文字列 (1 BTR = 10^18 wei)
// ============================================================
import { Ed25519 } from './crypto.js';
const DELIMITER = '\nLINE_BREAK\n';
const BTR_ADDRESS = '0x0000000000000000';
const SEEDS_CDN = 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/fullserver/seeds.json';
const WEI_PER_BTR = 1000000000000000000n;
const GAS_FEE_WEI = (1n * WEI_PER_BTR).toString();
let seedsList = [];
let currentSeedHost = '';
let wsReconnectDelay = 1000;
// ============================================================
// 状態
// ============================================================
let ws = null;
let wallet = null;
let balance = "0";
let tokenBalances = {};
let tokenInfoCache = {};
let miningTargetToken = '';
let isMining = false;
let mineWorker = null;
let workerBlobURL = null;
let minedCount = 0;
let chainHeight = 0;
let currentDifficulty = 1;
let nonce = 0;
let miningStartTime = 0;
let totalHashes = 0;
let latestBlockHash = '0'.repeat(64);
let latestReward = (100n * WEI_PER_BTR).toString();
let pendingTransactions = [];
let lastProcessedHash = ''; // 重複ブロック排除用
let lastProcessedTime = 0;
// ============================================================
// Wei変換ヘルパー
// ============================================================
function btrToWei(btr) {
    if (typeof btr === 'string')
        btr = parseFloat(btr);
    if (isNaN(btr) || btr < 0)
        return "0";
    const str = btr.toFixed(18);
    const [wholePart, fracPart = ''] = str.split('.');
    const whole = BigInt(wholePart) * WEI_PER_BTR;
    const frac = BigInt(fracPart.padEnd(18, '0').slice(0, 18));
    return (whole + frac).toString();
}
function weiToBtr(wei, decimals = 18) {
    try {
        const weiNum = BigInt(wei);
        if (weiNum < 0n)
            return "0";
        const whole = weiNum / WEI_PER_BTR;
        const fraction = weiNum % WEI_PER_BTR;
        const fractionStr = fraction.toString().padStart(18, '0');
        const trimmed = fractionStr.slice(0, decimals).replace(/0+$/, '');
        if (trimmed === '')
            return whole.toString();
        return `${whole}.${trimmed}`;
    }
    catch {
        return "0";
    }
}
function compareWei(a, b) {
    const diff = BigInt(a || "0") - BigInt(b || "0");
    if (diff > 0n)
        return 1;
    if (diff < 0n)
        return -1;
    return 0;
}
// ============================================================
// 共通ヘルパー
// ============================================================
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++)
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
}
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer.buffer);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function addLog(boxId, msg, type = '') {
    const box = document.getElementById(boxId);
    if (!box)
        return;
    const time = new Date().toLocaleTimeString();
    const cls = type ? ` class="${type}"` : '';
    box.innerHTML += `<div${cls}>[${time}] ${msg}</div>`;
    box.scrollTop = box.scrollHeight;
}
function $(id) { return document.getElementById(id); }
function $val(id) { return document.getElementById(id).value.trim(); }
function switchTab(panelName) {
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const btn = document.querySelector(`nav button[data-panel="${panelName}"]`);
    if (btn)
        btn.classList.add('active');
    const panel = $(`panel-${panelName}`);
    if (panel)
        panel.classList.add('active');
}
// ============================================================
// アップデートチェック（切断時にCDNを確認）
// ============================================================
let currentScriptHash = '';
async function checkForUpdate() {
    try {
        // 現在のページのHTMLを再取得してスクリプトが変わってないか確認
        const res = await fetch(window.location.href, { cache: 'no-cache' });
        if (!res.ok)
            return;
        const html = await res.text();
        const hash = await sha256(html);
        if (!currentScriptHash) {
            currentScriptHash = hash; // 初回は記録だけ
            return;
        }
        if (hash !== currentScriptHash) {
            addLog('globalLog', 'アップデート検出、リロードします...', 'success');
            setTimeout(() => window.location.reload(), 1000);
        }
    }
    catch {
        // ネットワーク不通なら無視
    }
}
// ============================================================
// WebSocket (seeds.jsonからランダム選択、WSS 443)
// ============================================================
async function fetchSeeds() {
    try {
        const res = await fetch(SEEDS_CDN);
        if (!res.ok)
            return [];
        const data = await res.json();
        return data.seeds || [];
    }
    catch {
        return [];
    }
}
function getRandomSeedURL() {
    if (seedsList.length === 0)
        return 'wss://mail.shudo-physics.com:443';
    // 現在接続中以外からランダム選択
    const candidates = seedsList.filter(s => s.host !== currentSeedHost);
    const seed = candidates.length > 0
        ? candidates[Math.floor(Math.random() * candidates.length)]
        : seedsList[Math.floor(Math.random() * seedsList.length)];
    currentSeedHost = seed.host;
    return `wss://${seed.host}:443`;
}
async function connect() {
    // 初回はseeds.jsonを取得
    if (seedsList.length === 0) {
        seedsList = await fetchSeeds();
    }
    const url = getRandomSeedURL();
    addLog('globalLog', `シード接続中: ${currentSeedHost}`, 'info');
    ws = new WebSocket(url);
    ws.onopen = () => {
        $('statusDot').classList.add('connected');
        $('statusText').textContent = '接続中';
        addLog('globalLog', `✅ ${currentSeedHost} 接続成功`, 'success');
        wsReconnectDelay = 1000; // リセット
        if (wallet) {
            requestBalance();
            requestHeight();
            requestLatestBlock();
        }
    };
    ws.onmessage = (event) => {
        const parts = event.data.split(DELIMITER);
        for (const part of parts) {
            if (!part.trim())
                continue;
            try {
                handlePacket(JSON.parse(part));
            }
            catch { }
        }
    };
    ws.onclose = () => {
        $('statusDot').classList.remove('connected');
        $('statusText').textContent = '切断';
        // 別シードへ指数バックオフ再接続
        const delay = Math.min(wsReconnectDelay, 20000);
        wsReconnectDelay = Math.min(wsReconnectDelay * 2, 20000);
        addLog('globalLog', `切断 → ${delay / 1000}秒後に別シードへ`, 'error');
        checkForUpdate().then(() => {
            setTimeout(connect, delay);
        });
    };
    ws.onerror = () => { addLog('globalLog', '接続エラー', 'error'); };
}
function send(packet) {
    if (ws && ws.readyState === WebSocket.OPEN)
        ws.send(JSON.stringify(packet) + DELIMITER);
}
// ============================================================
// パケットハンドリング
// ============================================================
function handlePacket(packet) {
    switch (packet.type) {
        case 'balance':
            balance = String(packet.data.balance || "0");
            // tokensはWei文字列のRecord
            tokenBalances = {};
            if (packet.data.tokens) {
                for (const [addr, val] of Object.entries(packet.data.tokens)) {
                    tokenBalances[addr] = String(val);
                }
            }
            const newNonce = packet.data.pendingNonce ?? packet.data.nonce ?? 0;
            const confirmedNonce = packet.data.nonce ?? 0;
            if (newNonce !== nonce) {
                addLog('globalLog', `Nonce更新: ${nonce} → ${newNonce} (確定=${confirmedNonce})`, 'info');
            }
            nonce = newNonce;
            for (const addr of Object.keys(tokenBalances)) {
                if (!tokenInfoCache[addr])
                    send({ type: 'get_token', data: { address: addr } });
            }
            updateBalanceUI();
            updateMiningTokenSelect();
            break;
        case 'height':
            chainHeight = packet.data.height || 0;
            if (packet.data.latestHash)
                latestBlockHash = packet.data.latestHash;
            if (packet.data.difficulty)
                currentDifficulty = packet.data.difficulty;
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            break;
        case 'chain_chunk': {
            const blocks = packet.data?.blocks;
            if (blocks && blocks.length > 0) {
                const lastBlock = blocks[blocks.length - 1];
                latestBlockHash = lastBlock.hash;
                const newHeight = lastBlock.height + 1;
                if (newHeight > chainHeight) {
                    addLog('globalLog', `同期: #${chainHeight} → #${newHeight} (${blocks.length}ブロック受信)`, 'info');
                    chainHeight = newHeight;
                }
                $('chainHeight').textContent = String(chainHeight);
            }
            break;
        }
        case 'new_block': {
            const blk = packet.data;
            if (!blk)
                break;
            // 重複排除: 同じハッシュのブロックは無視
            const blkHash = blk.hash || '';
            if (blkHash && blkHash === lastProcessedHash && Date.now() - lastProcessedTime < 5000)
                break;
            if (blkHash) {
                lastProcessedHash = blkHash;
                lastProcessedTime = Date.now();
            }
            const newHeight = (blk.height || 0) + 1;
            if (newHeight > chainHeight)
                chainHeight = newHeight;
            latestBlockHash = blk.hash || latestBlockHash;
            if (blk.difficulty)
                currentDifficulty = blk.difficulty;
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            const minerAddr = blk.miner ? blk.miner.slice(0, 10) + '...' : '不明';
            const isMe = wallet && blk.miner === wallet.address;
            const reward = blk.reward ? weiToBtr(String(blk.reward), 2) : '?';
            addLog('globalLog', `新ブロック #${blk.height} by ${isMe ? 'あなた' : minerAddr} (${reward} BTR, diff=${currentDifficulty})`, 'success');
            if (isMining) {
                addLog('miningLog', `新ブロック検出 #${blk.height} by ${isMe ? 'あなた' : minerAddr} → テンプレート再取得`, 'info');
                cleanupWorker();
                miningStartTime = Date.now();
                totalHashes = 0;
                requestBlockTemplate();
            }
            if (wallet)
                requestBalance();
            break;
        }
        case 'tx_result':
            if (packet.data.success) {
                addLog('globalLog', `✅ Tx成功: ${packet.data.txType} (nonce=${packet.data.nonce})`, 'success');
            }
            else {
                addLog('globalLog', `❌ Tx失敗: ${packet.data.error} (ローカルnonce=${nonce})`, 'error');
            }
            if (wallet)
                requestBalance();
            break;
        case 'rate': {
            if (packet.data.rate != null) {
                const rateTokenAddr = packet.data.tokenAddress || '';
                const rateInfo = tokenInfoCache[rateTokenAddr];
                const rateLabel = rateInfo ? rateInfo.symbol : rateTokenAddr.slice(0, 10) + '...';
                const rateBtr = weiToBtr(String(packet.data.rate), 18);
                $('swapRate').textContent = `レート: 1 ${rateLabel} = ${rateBtr} BTR`;
            }
            else {
                $('swapRate').textContent = 'レート: 取得失敗';
            }
            break;
        }
        case 'token_info': {
            const ti = packet.data?.token;
            if (ti && ti.address) {
                tokenInfoCache[ti.address] = { symbol: ti.symbol, name: ti.name };
                updateBalanceUI();
                updateMiningTokenSelect();
            }
            break;
        }
        case 'tokens_list': {
            const list = packet.data?.tokens || [];
            for (const t of list)
                tokenInfoCache[t.address] = { symbol: t.symbol, name: t.name };
            updateMiningTokenSelect();
            if (window.__pendingTokenSearch) {
                const query = window.__pendingTokenSearch;
                window.__pendingTokenSearch = null;
                showTokenSearchResults(query, list);
            }
            break;
        }
        case 'block_template': {
            const tmpl = packet.data;
            if (tmpl) {
                // 重複テンプレート抑制: 同じheight+previousHashなら無視
                const tmplKey = `${tmpl.height}:${tmpl.previousHash}`;
                if (window.__lastTmplKey === tmplKey && Date.now() - (window.__lastTmplTime || 0) < 3000)
                    break;
                window.__lastTmplKey = tmplKey;
                window.__lastTmplTime = Date.now();
                chainHeight = tmpl.height || chainHeight;
                latestBlockHash = tmpl.previousHash || latestBlockHash;
                currentDifficulty = tmpl.difficulty || currentDifficulty;
                latestReward = String(tmpl.reward || latestReward);
                pendingTransactions = tmpl.transactions || [];
                $('chainHeight').textContent = String(chainHeight);
                $('difficulty').textContent = String(currentDifficulty);
                addLog('miningLog', `テンプレート: height=${chainHeight} tx=${pendingTransactions.length} diff=${currentDifficulty} reward=${weiToBtr(latestReward, 2)} BTR`, 'info');
                if (isMining)
                    startMineWorker();
            }
            break;
        }
        case 'block_accepted': {
            const acc = packet.data;
            // 重複排除: 同じハッシュの承認は無視
            const accHash = acc.hash || '';
            if (accHash && accHash === lastProcessedHash && Date.now() - lastProcessedTime < 5000)
                break;
            if (accHash) {
                lastProcessedHash = accHash;
                lastProcessedTime = Date.now();
            }
            chainHeight = acc.height || chainHeight;
            latestBlockHash = acc.hash || latestBlockHash;
            currentDifficulty = acc.difficulty || currentDifficulty;
            latestReward = String(acc.reward || latestReward);
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            $('minedBlocks').textContent = String(minedCount);
            addLog('miningLog', `ブロック承認! height=${chainHeight} reward=${weiToBtr(latestReward, 2)} BTR`, 'success');
            if (wallet)
                requestBalance();
            // 自動スワップ
            if (miningTargetToken && wallet) {
                const swapAmount = String(acc.reward || latestReward);
                const info = tokenInfoCache[miningTargetToken];
                addLog('miningLog', `自動スワップ: ${weiToBtr(swapAmount, 2)} BTR → ${info ? info.symbol : miningTargetToken.slice(0, 10)}...`, 'info');
                signAndSend({
                    type: 'swap',
                    token: BTR_ADDRESS,
                    data: { tokenIn: BTR_ADDRESS, tokenOut: miningTargetToken, amountIn: swapAmount }
                });
            }
            if (isMining) {
                cleanupWorker();
                miningStartTime = Date.now();
                totalHashes = 0;
                requestBlockTemplate();
            }
            break;
        }
        case 'difficulty_update': {
            const upd = packet.data;
            const oldDiff = currentDifficulty;
            currentDifficulty = upd.difficulty || currentDifficulty;
            chainHeight = upd.height || chainHeight;
            latestBlockHash = upd.previousHash || latestBlockHash;
            latestReward = String(upd.reward || latestReward);
            $('difficulty').textContent = String(currentDifficulty);
            $('chainHeight').textContent = String(chainHeight);
            const dir = currentDifficulty > oldDiff ? '難易度UP' : currentDifficulty < oldDiff ? '難易度DOWN' : '難易度更新';
            addLog('miningLog', `${dir}: diff=${currentDifficulty} (height=${chainHeight})`, 'info');
            if (isMining) {
                cleanupWorker();
                miningStartTime = Date.now();
                totalHashes = 0;
                requestBlockTemplate();
            }
            break;
        }
        case 'block_rejected': {
            const rej = packet.data;
            currentDifficulty = rej.difficulty || currentDifficulty;
            chainHeight = rej.height || chainHeight;
            latestBlockHash = rej.hash || latestBlockHash;
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            addLog('miningLog', `ブロック拒否: ${rej.error}`, 'error');
            if (isMining) {
                cleanupWorker();
                miningStartTime = Date.now();
                totalHashes = 0;
                requestBlockTemplate();
            }
            break;
        }
        case 'random_result':
            addLog('miningLog', `乱数更新: ${(packet.data.random || '').slice(0, 16)}...`, 'info');
            break;
        case 'new_tx': {
            // 新txをブロックに含めるためテンプレート再取得（3秒デバウンス）
            if (isMining) {
                if (window.__newTxDebounce)
                    clearTimeout(window.__newTxDebounce);
                window.__newTxDebounce = setTimeout(() => {
                    if (isMining && mineWorker) {
                        cleanupWorker();
                        miningStartTime = Date.now();
                        totalHashes = 0;
                        requestBlockTemplate();
                    }
                }, 3000);
            }
            break;
        }
        case 'error':
            addLog('globalLog', `エラー: ${packet.data.message}`, 'error');
            break;
        case 'sync_busy':
            addLog('globalLog', `ノード同期中: ${packet.data?.message || 'しばらくお待ちください'}`, 'info');
            // 5秒後にリトライ
            setTimeout(() => {
                if (wallet) {
                    send({ type: 'get_balance', data: { address: wallet.address } });
                    send({ type: 'get_height' });
                }
            }, 5000);
            break;
    }
}
// ============================================================
// リクエスト
// ============================================================
function requestBalance() {
    if (!wallet)
        return;
    send({ type: 'get_balance', data: { address: wallet.address } });
}
function requestHeight() {
    send({ type: 'get_height', data: {} });
}
function requestLatestBlock() {
    send({ type: 'get_chain', data: { from: Math.max(0, chainHeight - 1), to: chainHeight } });
}
function requestBlockTemplate() {
    if (!wallet)
        return;
    send({ type: 'get_block_template', data: { miner: wallet.address } });
}
// ============================================================
// ウォレット
// ============================================================
async function createWallet() {
    const privateKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const privateKey = bytesToHex(privateKeyBytes);
    try {
        const pubBytes = await Ed25519.getPublicKey(privateKeyBytes);
        const publicKey = bytesToHex(pubBytes);
        const address = '0x' + (await sha256(publicKey)).slice(0, 40);
        wallet = { privateKey, publicKey, address };
        saveWallet();
        updateWalletUI();
        addLog('globalLog', 'ウォレット作成完了', 'success');
        requestBalance();
    }
    catch (e) {
        addLog('globalLog', `ウォレット作成失敗: ${e instanceof Error ? e.message : String(e)}`, 'error');
    }
}
async function importWallet() {
    const key = $val('importKey');
    if (key.length !== 64) {
        addLog('globalLog', '秘密鍵は64文字のhex', 'error');
        return;
    }
    try {
        const privBytes = hexToBytes(key);
        const pubBytes = await Ed25519.getPublicKey(privBytes);
        const publicKey = bytesToHex(pubBytes);
        const address = '0x' + (await sha256(publicKey)).slice(0, 40);
        wallet = { privateKey: key, publicKey, address };
        saveWallet();
        updateWalletUI();
        addLog('globalLog', 'ウォレットインポート完了', 'success');
        requestBalance();
    }
    catch (e) {
        addLog('globalLog', `インポート失敗: ${e instanceof Error ? e.message : String(e)}`, 'error');
    }
}
function exportWallet() {
    if (!wallet) {
        addLog('globalLog', 'ウォレットがありません', 'error');
        return;
    }
    const data = `秘密鍵: ${wallet.privateKey}\n公開鍵: ${wallet.publicKey}\nアドレス: ${wallet.address}`;
    navigator.clipboard.writeText(data).then(() => addLog('globalLog', 'クリップボードにコピー', 'success'));
}
function saveWallet() {
    if (!wallet)
        return;
    localStorage.setItem('btr_wallet', JSON.stringify(wallet));
}
async function loadWallet() {
    const saved = localStorage.getItem('btr_wallet');
    if (!saved)
        return;
    try {
        wallet = JSON.parse(saved);
        updateWalletUI();
        addLog('globalLog', 'ウォレット復元', 'success');
    }
    catch {
        addLog('globalLog', 'ウォレット復元失敗', 'error');
    }
}
function updateWalletUI() {
    if (!wallet)
        return;
    $('myAddress').textContent = wallet.address;
    $('myPubKey').textContent = wallet.publicKey;
    $('btnCreate').textContent = 'ウォレット再作成（上書き）';
}
// ============================================================
// 残高表示 (Wei → BTR)
// ============================================================
function updateBalanceUI() {
    $('btrBalance').textContent = weiToBtr(balance, 6);
    $('nonceDisplay').textContent = String(nonce);
    const tokenKeys = Object.keys(tokenBalances).filter(addr => {
        try {
            return BigInt(tokenBalances[addr]) > 0n;
        }
        catch {
            return false;
        }
    });
    if (tokenKeys.length > 0) {
        $('tokenBalances').style.display = 'block';
        $('tokenList').innerHTML = tokenKeys.map(addr => {
            const bal = weiToBtr(tokenBalances[addr], 6);
            const info = tokenInfoCache[addr];
            const label = info
                ? `${info.symbol} <span style="color:var(--text2);font-size:11px">${info.name}</span> <span style="color:var(--text2);font-size:10px;opacity:0.6">${addr.slice(0, 10)}...</span>`
                : `<span style="color:var(--text2);font-size:11px">${addr}</span>`;
            return `<div class="token-item"><span>${label}</span><span>${bal}</span></div>`;
        }).join('');
    }
    else {
        $('tokenBalances').style.display = 'none';
    }
}
// ============================================================
// 署名 & 送信
// ============================================================
async function signAndSend(txData) {
    if (!wallet) {
        addLog('globalLog', 'ウォレットがありません', 'error');
        return;
    }
    const tx = {
        ...txData,
        from: wallet.address,
        publicKey: wallet.publicKey,
        fee: GAS_FEE_WEI,
        nonce,
        timestamp: Date.now(),
        signature: '',
    };
    const { signature: _, ...rest } = tx;
    const message = canonicalJSON(rest);
    const msgBytes = new TextEncoder().encode(message);
    try {
        const privBytes = hexToBytes(wallet.privateKey);
        const sigBytes = await Ed25519.sign(msgBytes, privBytes);
        tx.signature = bytesToHex(sigBytes);
        send({ type: 'tx', data: tx });
        addLog('globalLog', `Tx送信: ${tx.type} (nonce=${nonce})`, 'info');
        nonce++;
    }
    catch (e) {
        addLog('globalLog', `署名失敗: ${e instanceof Error ? e.message : String(e)}`, 'error');
    }
}
// ============================================================
// 送金 (BTR → Wei変換)
// ============================================================
async function sendBTR() {
    const to = $val('sendTo');
    const amountBtr = parseFloat($val('sendAmount'));
    if (!to || isNaN(amountBtr) || amountBtr <= 0) {
        addLog('globalLog', '宛先と金額を入力', 'error');
        return;
    }
    const amountWei = btrToWei(amountBtr);
    await signAndSend({ type: 'transfer', token: BTR_ADDRESS, to, amount: amountWei });
}
async function sendToken() {
    const token = $val('tokenSendToken');
    const to = $val('tokenSendTo');
    const amountBtr = parseFloat($val('tokenSendAmount'));
    if (!token || !to || isNaN(amountBtr) || amountBtr <= 0) {
        addLog('globalLog', '全項目を入力', 'error');
        return;
    }
    const amountWei = btrToWei(amountBtr);
    await signAndSend({ type: 'token_transfer', token, to, amount: amountWei });
}
async function createToken() {
    const symbol = $val('tokenSymbol');
    const name = $val('tokenName');
    const totalSupplyBtr = parseInt($val('tokenSupply'));
    if (!symbol || !name || isNaN(totalSupplyBtr) || totalSupplyBtr <= 0) {
        addLog('globalLog', '全項目を入力', 'error');
        return;
    }
    const totalSupplyWei = btrToWei(totalSupplyBtr);
    // 全量AMMプール投入
    await signAndSend({
        type: 'create_token', token: BTR_ADDRESS,
        data: { symbol, name, totalSupply: totalSupplyWei, poolRatio: 1, distribution: 'amm' }
    });
    addLog('globalLog', `トークン ${symbol} 作成中... (全量AMMプールに投入)`, 'info');
}
async function executeSwap() {
    const tokenIn = $val('swapIn') || BTR_ADDRESS;
    const tokenOut = $val('swapOut');
    const amountInBtr = parseFloat($val('swapAmount'));
    if (!tokenOut || isNaN(amountInBtr) || amountInBtr <= 0) {
        addLog('globalLog', '全項目を入力', 'error');
        return;
    }
    const amountInWei = btrToWei(amountInBtr);
    await signAndSend({
        type: 'swap', token: BTR_ADDRESS,
        data: { tokenIn, tokenOut, amountIn: amountInWei }
    });
}
function requestSwapRate() {
    const tokenIn = $val('swapIn') || BTR_ADDRESS;
    const tokenOut = $val('swapOut');
    const tokenAddr = tokenIn !== BTR_ADDRESS ? tokenIn : tokenOut;
    if (tokenAddr && tokenAddr !== BTR_ADDRESS && tokenAddr.length > 4) {
        send({ type: 'get_rate', data: { address: tokenAddr } });
        $('swapRate').textContent = 'レート: 取得中...';
    }
}
// ============================================================
// トークン検索
// ============================================================
function searchToken() {
    const query = $val('tokenSearch').toUpperCase();
    if (!query) {
        $('tokenSearchResults').innerHTML = '<div style="color:var(--text2);font-size:12px">シンボルを入力してください</div>';
        return;
    }
    $('tokenSearchResults').innerHTML = '<div style="color:var(--text2);font-size:12px">検索中...</div>';
    window.__pendingTokenSearch = query;
    send({ type: 'get_tokens_list', data: {} });
}
function showTokenSearchResults(query, allTokens) {
    const matches = allTokens.filter(t => t.symbol.toUpperCase().includes(query) || t.name.toUpperCase().includes(query));
    if (matches.length === 0) {
        $('tokenSearchResults').innerHTML = '<div style="color:var(--text2);font-size:12px">見つかりませんでした</div>';
        return;
    }
    $('tokenSearchResults').innerHTML = matches.map(t => {
        const supplyBtr = weiToBtr(t.totalSupply, 2);
        return `<div class="token-item" style="flex-direction:column;gap:4px;cursor:pointer" data-addr="${t.address}">
      <div><strong style="color:var(--accent)">${t.symbol}</strong> <span style="color:var(--text2)">${t.name}</span></div>
      <div style="font-size:10px;color:var(--text2)">${t.address}　供給量: ${supplyBtr}</div>
    </div>`;
    }).join('');
    $('tokenSearchResults').querySelectorAll('[data-addr]').forEach((el) => {
        el.addEventListener('click', () => {
            const addr = el.dataset.addr || '';
            navigator.clipboard.writeText(addr);
            addLog('globalLog', `アドレスコピー: ${addr}`, 'success');
        });
    });
}
function updateMiningTokenSelect() {
    const select = document.getElementById('miningTarget');
    if (!select)
        return;
    const prev = select.value;
    let html = '<option value="">BTR（そのまま）</option>';
    const allTokenAddrs = new Set([...Object.keys(tokenBalances), ...Object.keys(tokenInfoCache)]);
    for (const addr of allTokenAddrs) {
        const info = tokenInfoCache[addr];
        const label = info ? `${info.symbol} (${info.name})` : addr.slice(0, 16) + '...';
        html += `<option value="${addr}">${label}</option>`;
    }
    select.innerHTML = html;
    select.value = prev || '';
}
// ============================================================
// マイニング
// ============================================================
function toggleMining() {
    if (!wallet) {
        addLog('miningLog', 'ウォレットがありません', 'error');
        return;
    }
    if (isMining)
        stopMining();
    else
        startMining();
}
function startMining() {
    if (!wallet)
        return;
    isMining = true;
    $('btnMine').textContent = '⏸ マイニング停止';
    addLog('miningLog', 'マイニング開始', 'success');
    const select = document.getElementById('miningTarget');
    miningTargetToken = select ? select.value : '';
    miningStartTime = Date.now();
    totalHashes = 0;
    requestBlockTemplate();
    startHashRateUpdate();
}
function stopMining() {
    isMining = false;
    cleanupWorker();
    if (window.__hashRateTimer) {
        clearInterval(window.__hashRateTimer);
        window.__hashRateTimer = null;
    }
    $('btnMine').textContent = '▶ マイニング開始';
    $('hashRate').textContent = '0 H/s';
    addLog('miningLog', 'マイニング停止', 'info');
}
function cleanupWorker() {
    if (mineWorker) {
        mineWorker.terminate();
        mineWorker = null;
    }
    // workerBlobURLは使い回すので解放しない
}
function startHashRateUpdate() {
    if (window.__hashRateTimer)
        clearInterval(window.__hashRateTimer);
    window.__hashRateTimer = setInterval(() => {
        if (!isMining)
            return;
        const elapsed = (Date.now() - miningStartTime) / 1000;
        if (elapsed > 0) {
            const rate = Math.floor(totalHashes / elapsed);
            $('hashRate').textContent = rate >= 1000
                ? (rate / 1000).toFixed(1) + ' KH/s'
                : rate + ' H/s';
        }
    }, 1000);
}
function startMineWorker() {
    if (!wallet || !isMining)
        return;
    const blockData = {
        height: chainHeight,
        previousHash: latestBlockHash,
        timestamp: Date.now(),
        nonce: 0,
        difficulty: currentDifficulty,
        miner: wallet.address,
        reward: latestReward,
        transactions: pendingTransactions,
        hash: '',
    };
    // Workerが生きていたら新しいデータを送るだけ（再作成しない）
    if (mineWorker) {
        blockData.timestamp = Date.now();
        mineWorker.postMessage(blockData);
        return;
    }
    // blob URLは一度だけ作成して使い回す
    if (!workerBlobURL) {
        const workerCode = `
    function sha256(data) {
      const enc = new TextEncoder().encode(data);
      return crypto.subtle.digest('SHA-256', enc).then(buf =>
        Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
      );
    }

    function computeBlockHash(block) {
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

    function meetsTarget(hash, difficulty) {
      const fullNibbles = Math.floor(difficulty / 4);
      const remainBits = difficulty % 4;
      for (let i = 0; i < fullNibbles; i++) {
        if (hash[i] !== '0') return false;
      }
      if (remainBits > 0 && fullNibbles < hash.length) {
        const v = parseInt(hash[fullNibbles], 16);
        if (v > (1 << (4 - remainBits)) - 1) return false;
      }
      return true;
    }

    onmessage = async (e) => {
      const block = e.data;
      let attempts = 0;
      const maxAttempts = 100000;

      while (attempts < maxAttempts) {
        block.nonce = Math.floor(Math.random() * 1e15);
        const hash = await computeBlockHash(block);
        attempts++;

        if (meetsTarget(hash, block.difficulty)) {
          block.hash = hash;
          postMessage({ success: true, block, attempts });
          return;
        }
      }

      postMessage({ success: false, attempts });
    };
    `;
        const blob = new Blob([workerCode], { type: 'application/javascript' });
        workerBlobURL = URL.createObjectURL(blob);
    }
    mineWorker = new Worker(workerBlobURL);
    mineWorker.onmessage = (e) => {
        totalHashes += e.data.attempts || 0;
        if (e.data.success) {
            const block = e.data.block;
            minedCount++;
            $('minedBlocks').textContent = String(minedCount);
            addLog('miningLog', `ブロック発見! nonce=${block.nonce} hash=${block.hash.slice(0, 16)}...`, 'success');
            send({ type: 'block_broadcast', data: { ...block, minerId: wallet?.address } });
            // 発見後はWorkerを破棄（新テンプレートで再作成される）
            if (mineWorker) {
                mineWorker.terminate();
                mineWorker = null;
            }
        }
        else {
            // 10万回失敗 → 同じWorkerに新データを送る（再作成しない）
            if (isMining && mineWorker) {
                const retryData = {
                    height: chainHeight,
                    previousHash: latestBlockHash,
                    timestamp: Date.now(),
                    nonce: 0,
                    difficulty: currentDifficulty,
                    miner: wallet?.address || '',
                    reward: latestReward,
                    transactions: pendingTransactions,
                    hash: '',
                };
                mineWorker.postMessage(retryData);
            }
        }
    };
    mineWorker.onerror = (err) => {
        addLog('miningLog', `Worker エラー: ${err.message}`, 'error');
        if (mineWorker) {
            mineWorker.terminate();
            mineWorker = null;
        }
        if (isMining)
            setTimeout(startMineWorker, 1000);
    };
    mineWorker.postMessage(blockData);
}
// ============================================================
// QRコード
// ============================================================
function loadQRious() {
    return new Promise((resolve, reject) => {
        if (typeof window.QRious !== 'undefined') {
            resolve();
            return;
        }
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/qrious@4.0.2/dist/qrious.min.js';
        s.onload = () => resolve();
        s.onerror = () => reject(new Error('QRious読み込み失敗'));
        document.head.appendChild(s);
    });
}
async function showQR() {
    if (!wallet) {
        addLog('globalLog', 'ウォレットがありません', 'error');
        return;
    }
    const modal = $('qrModal');
    const canvasDiv = $('qrCanvas');
    const infoDiv = $('qrInfo');
    canvasDiv.innerHTML = '<div style="color:var(--text2);font-size:12px">生成中...</div>';
    infoDiv.innerHTML = '';
    modal.style.display = 'flex';
    const baseURL = window.location.origin + window.location.pathname;
    const amountStr = $val('qrAmount');
    let qrData = `${baseURL}?user=${wallet.address}`;
    if (amountStr && parseFloat(amountStr) > 0) {
        qrData += `&value=${amountStr}`;
    }
    try {
        await loadQRious();
        canvasDiv.innerHTML = '';
        const canvas = document.createElement('canvas');
        new window.QRious({ element: canvas, value: qrData, size: 220, background: '#ffffff', foreground: '#000000' });
        canvasDiv.appendChild(canvas);
    }
    catch {
        canvasDiv.innerHTML = '<div style="color:var(--red);font-size:12px">QR生成失敗</div>';
    }
    // アドレスと金額情報
    let info = wallet.address;
    if (amountStr && parseFloat(amountStr) > 0) {
        info += `<br><span style="color:var(--accent)">${amountStr} BTR</span>`;
    }
    info += `<br><span style="font-size:9px;opacity:0.6">${qrData}</span>`;
    infoDiv.innerHTML = info;
}
function hideQR() {
    $('qrModal').style.display = 'none';
}
// ============================================================
// URLパラメータ解析 → 送金画面に自動遷移
// ============================================================
function handleURLParams() {
    const params = new URLSearchParams(window.location.search);
    const user = params.get('user');
    if (!user)
        return;
    applyPaymentParams(user, params.get('value') || '');
    window.history.replaceState({}, '', window.location.pathname);
}
// 任意のURLから ?user= &value= を抽出して送金画面に反映
// f5.si でも .com でも、パラメータさえあれば動く
function parsePaymentURL(urlStr) {
    try {
        // 完全なURLの場合
        const url = new URL(urlStr);
        const user = url.searchParams.get('user');
        if (user)
            return { user, value: url.searchParams.get('value') || '' };
    }
    catch {
        // URLじゃない場合（0x...アドレス直書きなど）
        if (urlStr.startsWith('0x') && urlStr.length >= 42) {
            return { user: urlStr.slice(0, 42), value: '' };
        }
    }
    return null;
}
function applyPaymentParams(user, value) {
    switchTab('send');
    const sendToInput = $('sendTo');
    if (sendToInput)
        sendToInput.value = user;
    if (value && parseFloat(value) > 0) {
        const sendAmountInput = $('sendAmount');
        if (sendAmountInput)
            sendAmountInput.value = value;
    }
    addLog('globalLog', `送金先を設定: ${user.slice(0, 14)}...${value ? ' / ' + value + ' BTR' : ''}`, 'info');
}
// ============================================================
// DOM構築
// ============================================================
function buildUI() {
    document.body.innerHTML = `
<style>
:root{--bg:#0a0a0f;--bg2:#12121a;--bg3:#1a1a26;--border:#2a2a3a;--text:#e0e0e8;--text2:#8888a0;--accent:#00ff88;--accent2:#00cc6a;--red:#ff4466;--yellow:#ffcc00;--blue:#4488ff;--mono:'JetBrains Mono',monospace;--sans:'Noto Sans JP',sans-serif}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}
.logo{font-family:var(--mono);font-weight:700;font-size:20px;color:var(--accent);letter-spacing:2px}.logo span{color:var(--text2);font-weight:400;font-size:12px;margin-left:8px}
.status{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12px;color:var(--text2)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--red);transition:background .3s}.status-dot.connected{background:var(--accent);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
nav{background:var(--bg2);border-bottom:1px solid var(--border);display:flex;overflow-x:auto}
nav button{background:none;border:none;color:var(--text2);font-family:var(--mono);font-size:13px;padding:12px 20px;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap}
nav button:hover{color:var(--text)}nav button.active{color:var(--accent);border-bottom-color:var(--accent)}
main{max-width:800px;margin:0 auto;padding:24px 16px}
.panel{display:none}.panel.active{display:block}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-family:var(--mono);font-size:14px;color:var(--text2);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px}
.balance-display{font-family:var(--mono);font-size:36px;font-weight:700;color:var(--accent);margin:8px 0}.balance-display span{font-size:16px;color:var(--text2);font-weight:400}
.address-box{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:10px 14px;font-family:var(--mono);font-size:12px;color:var(--text2);word-break:break-all;cursor:pointer;transition:border-color .2s}.address-box:hover{border-color:var(--accent)}
.token-list{margin-top:12px}.token-item{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:13px}.token-item:last-child{border-bottom:none}
input,select{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:10px 14px;color:var(--text);font-family:var(--mono);font-size:13px;margin-bottom:12px;outline:none;transition:border-color .2s}
input:focus,select:focus{border-color:var(--accent)}input::placeholder{color:var(--text2)}
label{display:block;font-family:var(--mono);font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
button.btn{background:var(--accent);color:var(--bg);border:none;border-radius:4px;padding:10px 20px;font-family:var(--mono);font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;width:100%}
button.btn:hover{background:var(--accent2)}button.btn:disabled{opacity:.3;cursor:not-allowed}button.btn.danger{background:var(--red)}button.btn.secondary{background:var(--bg3);color:var(--text);border:1px solid var(--border)}
.mining-stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
.stat-box{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:12px}
.stat-box .label{font-family:var(--mono);font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:1px}
.stat-box .value{font-family:var(--mono);font-size:18px;font-weight:700;color:var(--text);margin-top:4px}.hashrate{color:var(--yellow)!important}
.log-box{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:12px;max-height:200px;overflow-y:auto;font-family:var(--mono);font-size:11px;color:var(--text2);line-height:1.6}
.log-box .success{color:var(--accent)}.log-box .error{color:var(--red)}.log-box .info{color:var(--blue)}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
@media(max-width:600px){.balance-display{font-size:28px}.mining-stats{grid-template-columns:1fr}nav button{padding:10px 14px;font-size:12px}}
.gap{height:8px}
.refresh-fab{position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:50%;background:var(--accent);color:var(--bg);border:none;font-size:22px;cursor:pointer;z-index:500;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 16px rgba(0,255,136,0.3);transition:all .2s}
.refresh-fab:hover{background:var(--accent2);transform:scale(1.1)}
.refresh-fab.cooldown{background:var(--bg3);color:var(--text2);cursor:not-allowed;box-shadow:none}
.refresh-fab.cooldown:hover{transform:none}
.refresh-fab svg{width:24px;height:24px;transition:transform .4s}
.refresh-fab:not(.cooldown):active svg{transform:rotate(360deg)}
.refresh-timer{position:absolute;bottom:-6px;right:-6px;background:var(--bg2);border:2px solid var(--border);border-radius:10px;font-family:var(--mono);font-size:9px;color:var(--text2);padding:1px 5px;min-width:22px;text-align:center}
</style>
<header>
  <div class="logo">BTR<span>Buturi Coin</span></div>
  <div class="status"><div class="status-dot" id="statusDot"></div><span id="statusText">未接続</span></div>
</header>
<nav id="nav">
  <button class="active" data-panel="wallet">ウォレット</button>
  <button data-panel="send">送金</button>
  <button data-panel="mining">マイニング</button>
  <button data-panel="tokens">トークン</button>
  <button data-panel="swap">スワップ</button>
  <button data-panel="explorer">チェーン</button>
</nav>
<main>
  <div class="panel active" id="panel-wallet">
    <div class="card"><h2>残高</h2><div class="balance-display"><span id="btrBalance">0</span> <span>BTR</span></div><div style="font-size:11px;color:var(--text2);margin-top:4px">nonce: <span id="nonceDisplay">0</span></div></div>
    <div class="card"><h2>アドレス</h2><div class="address-box" id="myAddress">ウォレット未作成</div></div>
    <div class="card"><h2>公開鍵</h2><div class="address-box" id="myPubKey">-</div></div>
    <div class="card" id="tokenBalances" style="display:none"><h2>トークン残高</h2><div class="token-list" id="tokenList"></div></div>
    <div class="card">
      <h2>ウォレット管理</h2>
      <button class="btn" id="btnCreate">新規ウォレット作成</button><div class="gap"></div>
      <button class="btn secondary" id="btnExport">秘密鍵エクスポート</button><div class="gap"></div>
      <label>秘密鍵インポート</label><input type="password" id="importKey" placeholder="hex 64文字">
      <button class="btn secondary" id="btnImport">インポート</button>
    </div>
  </div>
  <div class="panel" id="panel-send">
    <div class="card"><h2>BTR送金</h2>
      <label>宛先アドレス</label><input type="text" id="sendTo" placeholder="0x...">
      <label>金額 (BTR)</label><input type="number" id="sendAmount" placeholder="0" step="0.1" min="0">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">ガス代: 1 BTR</div>
      <button class="btn" id="btnSend">送金</button>
    </div>
    <div class="card"><h2>トークン送金</h2>
      <label>トークンアドレス</label><input type="text" id="tokenSendToken" placeholder="0x...">
      <label>宛先アドレス</label><input type="text" id="tokenSendTo" placeholder="0x...">
      <label>金額</label><input type="number" id="tokenSendAmount" placeholder="0" step="0.1" min="0">
      <button class="btn" id="btnTokenSend">送金</button>
    </div>
    <div class="card">
      <h2>受取用QRコード</h2>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">自分のアドレスをQRコードで表示します。相手がスキャンすると送金画面に飛びます。</div>
      <label>金額 (任意)</label><input type="number" id="qrAmount" placeholder="指定しない場合は空欄" step="0.1" min="0">
      <button class="btn secondary" id="btnShowQR">QRコード生成</button>
    </div>
  </div>
  <div class="panel" id="panel-mining">
    <div class="card"><h2>マイニング</h2>
      <div class="mining-stats">
        <div class="stat-box"><div class="label">ステータス</div><div class="value" id="miningStatus">停止中</div></div>
        <div class="stat-box"><div class="label">ハッシュレート</div><div class="value hashrate" id="hashRate">0 H/s</div></div>
        <div class="stat-box"><div class="label">難易度</div><div class="value" id="difficulty">-</div></div>
        <div class="stat-box"><div class="label">採掘ブロック</div><div class="value" id="minedBlocks">0</div></div>
      </div>
      <label>報酬の受け取り方</label>
      <select id="miningTarget"><option value="">BTR（そのまま）</option></select>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">トークンを選ぶと、ブロック報酬を自動でスワップします</div>
      <button class="btn" id="btnMine">▶ マイニング開始</button>
    </div>
    <div class="card"><h2>ログ</h2><div class="log-box" id="miningLog"></div></div>
  </div>
  <div class="panel" id="panel-tokens">
    <div class="card"><h2>トークン作成</h2>
      <label>シンボル</label><input type="text" id="tokenSymbol" placeholder="PHY" maxlength="10">
      <label>名前</label><input type="text" id="tokenName" placeholder="PhysicsCoin">
      <label>総供給量</label><input type="number" id="tokenSupply" placeholder="1000000" min="1">
      <div style="font-family:var(--mono);font-size:11px;color:var(--accent);margin-bottom:12px;padding:8px;background:var(--bg);border:1px solid var(--border);border-radius:4px">発行トークンは全量AMMプールに投入されます</div>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">作成費: 500 BTR + ガス代 1 BTR</div>
      <button class="btn" id="btnCreateToken">トークン作成</button>
    </div>
  </div>
  <div class="panel" id="panel-swap">
    <div class="card"><h2>スワップ (AMM)</h2>
      <label>売るトークン</label><input type="text" id="swapIn" placeholder="0x0000000000000000 (BTR)">
      <label>買うトークン</label><input type="text" id="swapOut" placeholder="トークンアドレス">
      <label>金額</label><input type="number" id="swapAmount" placeholder="0" step="0.1" min="0">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px" id="swapRate">レート: -</div>
      <button class="btn secondary" id="btnSwapRate" style="margin-bottom:8px">レート取得</button>
      <button class="btn" id="btnSwap">スワップ</button>
    </div>
  </div>
  <div class="panel" id="panel-explorer">
    <div class="card"><h2>チェーン情報</h2>
      <div class="mining-stats">
        <div class="stat-box"><div class="label">ブロック高さ</div><div class="value" id="chainHeight">-</div></div>
        <div class="stat-box"><div class="label">難易度</div><div class="value" id="explorerDifficulty">-</div></div>
      </div>
    </div>
    <div class="card"><h2>トークン検索</h2>
      <label>シンボルで検索</label>
      <input type="text" id="tokenSearch" placeholder="例: PHY">
      <button class="btn secondary" id="btnTokenSearch">検索</button>
      <div id="tokenSearchResults" style="margin-top:12px"></div>
    </div>
    <div class="card"><h2>ログ</h2><div class="log-box" id="globalLog"></div></div>
  </div>
</main>
<div id="qrModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:1000;justify-content:center;align-items:center">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:32px;max-width:360px;width:90%;position:relative">
    <button id="btnCloseQR" style="position:absolute;top:12px;right:16px;background:none;border:none;color:var(--text);font-size:24px;cursor:pointer;padding:4px;line-height:1">✕</button>
    <h2 style="font-family:var(--mono);font-size:16px;color:var(--accent);margin-bottom:16px;text-align:center">受取用QRコード</h2>
    <div id="qrCanvas" style="display:flex;justify-content:center;margin-bottom:16px;min-height:220px;align-items:center"></div>
    <div id="qrInfo" style="font-family:var(--mono);font-size:10px;color:var(--text2);word-break:break-all;text-align:center;line-height:1.6"></div>
  </div>
</div>
<button id="refreshFab" class="refresh-fab" title="更新">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
  <span id="refreshTimer" class="refresh-timer" style="display:none"></span>
</button>
`;
}
// ============================================================
// イベントバインド
// ============================================================
function bindEvents() {
    $('nav').addEventListener('click', (e) => {
        const target = e.target;
        if (target.tagName !== 'BUTTON')
            return;
        const panel = target.dataset.panel;
        if (!panel)
            return;
        document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        target.classList.add('active');
        $(`panel-${panel}`).classList.add('active');
    });
    $('btnCreate').addEventListener('click', () => createWallet());
    $('btnExport').addEventListener('click', () => exportWallet());
    $('btnImport').addEventListener('click', () => importWallet());
    $('myAddress').addEventListener('click', () => { if (wallet) {
        navigator.clipboard.writeText(wallet.address);
        addLog('globalLog', 'アドレスをコピー', 'success');
    } });
    $('myPubKey').addEventListener('click', () => { if (wallet) {
        navigator.clipboard.writeText(wallet.publicKey);
        addLog('globalLog', '公開鍵をコピー', 'success');
    } });
    $('btnSend').addEventListener('click', () => sendBTR());
    $('btnTokenSend').addEventListener('click', () => sendToken());
    $('sendAmount').addEventListener('keypress', (e) => { if (e.key === 'Enter')
        sendBTR(); });
    $('btnMine').addEventListener('click', () => toggleMining());
    $('miningTarget').addEventListener('change', () => {
        miningTargetToken = $('miningTarget').value;
        const info = tokenInfoCache[miningTargetToken];
        addLog('miningLog', miningTargetToken
            ? `報酬先: ${info ? info.symbol : miningTargetToken.slice(0, 10) + '...'}に自動スワップ`
            : '報酬先: BTR（そのまま）', 'info');
    });
    $('btnCreateToken').addEventListener('click', () => createToken());
    $('btnSwap').addEventListener('click', () => executeSwap());
    $('btnSwapRate').addEventListener('click', () => requestSwapRate());
    $('swapOut').addEventListener('input', () => {
        if (window.__rateDebounce)
            clearTimeout(window.__rateDebounce);
        window.__rateDebounce = setTimeout(requestSwapRate, 500);
    });
    $('swapIn').addEventListener('input', () => {
        if (window.__rateDebounce)
            clearTimeout(window.__rateDebounce);
        window.__rateDebounce = setTimeout(requestSwapRate, 500);
    });
    $('swapAmount').addEventListener('keypress', (e) => { if (e.key === 'Enter')
        executeSwap(); });
    $('btnTokenSearch').addEventListener('click', () => searchToken());
    $('tokenSearch').addEventListener('keydown', (e) => { if (e.key === 'Enter')
        searchToken(); });
    $('btnShowQR').addEventListener('click', () => showQR());
    $('btnCloseQR').addEventListener('click', () => hideQR());
    // モーダル背景クリックでも閉じる
    $('qrModal').addEventListener('click', (e) => {
        if (e.target.id === 'qrModal')
            hideQR();
    });
    // 更新FABボタン（15秒クールダウン）
    let refreshCooldown = false;
    $('refreshFab').addEventListener('click', () => {
        if (refreshCooldown)
            return;
        // 更新実行
        if (wallet && ws && ws.readyState === WebSocket.OPEN) {
            requestBalance();
            requestHeight();
            addLog('globalLog', '手動更新', 'info');
        }
        // クールダウン開始
        refreshCooldown = true;
        const fab = $('refreshFab');
        const timer = $('refreshTimer');
        fab.classList.add('cooldown');
        let remaining = 15;
        timer.textContent = String(remaining);
        timer.style.display = '';
        const cd = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
                clearInterval(cd);
                refreshCooldown = false;
                fab.classList.remove('cooldown');
                timer.style.display = 'none';
            }
            else {
                timer.textContent = String(remaining);
            }
        }, 1000);
    });
}
// ============================================================
// フォント読み込み
// ============================================================
function loadFonts() {
    const link = document.createElement('link');
    link.href = 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Noto+Sans+JP:wght@100..900&display=swap';
    link.rel = 'stylesheet';
    document.head.appendChild(link);
}
// ============================================================
// 初期化
// ============================================================
async function init() {
    loadFonts();
    buildUI();
    bindEvents();
    await loadWallet();
    connect();
    handleURLParams();
    // 初回のスクリプトハッシュを記録
    checkForUpdate();
    setInterval(() => {
        if (wallet && ws && ws.readyState === WebSocket.OPEN) {
            requestBalance();
            requestHeight();
        }
    }, 60000);
    addLog('globalLog', 'クライアント起動 (BigInt版)', 'info');
}
init();
//# sourceMappingURL=index.js.map