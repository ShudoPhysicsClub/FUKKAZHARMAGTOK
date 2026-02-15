// ============================================================
// BTR (Buturi Coin) - クライアント BigInt完全対応版
// crypto.ts の Ed25519 を使用
// 全金額は Wei文字列 (1 BTR = 10^18 wei)
// ============================================================
import { Ed25519 } from './crypto.js';
const DELIMITER = '\nLINE_BREAK\n';
const BTR_ADDRESS = '0x0000000000000000';
const WS_URL = 'wss://shudo-physics.f5.si:443';
const WEI_PER_BTR = 1000000000000000000n;
const GAS_FEE_WEI = (1n * WEI_PER_BTR).toString();
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
// WebSocket
// ============================================================
function connect() {
    addLog('globalLog', 'シードノードに接続中...', 'info');
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        $('statusDot').classList.add('connected');
        $('statusText').textContent = '接続中';
        addLog('globalLog', '接続成功', 'success');
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
        addLog('globalLog', '切断、3秒後に再接続...', 'error');
        setTimeout(connect, 3000);
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
            nonce = packet.data.nonce || 0;
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
                if (newHeight > chainHeight)
                    chainHeight = newHeight;
                $('chainHeight').textContent = String(chainHeight);
            }
            break;
        }
        case 'new_block': {
            const blk = packet.data;
            if (!blk)
                break;
            const newHeight = (blk.height || 0) + 1;
            if (newHeight > chainHeight)
                chainHeight = newHeight;
            latestBlockHash = blk.hash || latestBlockHash;
            if (blk.difficulty)
                currentDifficulty = blk.difficulty;
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            // 自分のブロックでもWorkerは再起動必要
            addLog('globalLog', `新ブロック #${blk.height} diff=${currentDifficulty}`, 'success');
            if (wallet)
                requestBalance();
            if (isMining) {
                cleanupWorker();
                miningStartTime = Date.now();
                totalHashes = 0;
                requestBlockTemplate();
            }
            break;
        }
        case 'tx_result':
            if (packet.data.success) {
                addLog('globalLog', `Tx成功: ${packet.data.txType}`, 'success');
            }
            else {
                addLog('globalLog', `Tx失敗: ${packet.data.error}`, 'error');
                if (nonce > 0)
                    nonce--;
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
                chainHeight = tmpl.height || chainHeight;
                latestBlockHash = tmpl.previousHash || latestBlockHash;
                currentDifficulty = tmpl.difficulty || currentDifficulty;
                latestReward = String(tmpl.reward || latestReward);
                pendingTransactions = tmpl.transactions || [];
                $('chainHeight').textContent = String(chainHeight);
                $('difficulty').textContent = String(currentDifficulty);
                addLog('miningLog', `テンプレート: height=${chainHeight} tx=${pendingTransactions.length} diff=${currentDifficulty}`, 'info');
                if (isMining)
                    startMineWorker();
            }
            break;
        }
        case 'block_accepted': {
            const acc = packet.data;
            chainHeight = acc.height || chainHeight;
            latestBlockHash = acc.hash || latestBlockHash;
            currentDifficulty = acc.difficulty || currentDifficulty;
            latestReward = String(acc.reward || latestReward);
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            $('minedBlocks').textContent = String(minedCount);
            addLog('miningLog', `ブロック承認! height=${chainHeight}`, 'success');
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
                }, 500);
            }
            break;
        }
        case 'error':
            addLog('globalLog', `エラー: ${packet.data.message}`, 'error');
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
        nonce++;
        addLog('globalLog', `Tx送信: ${tx.type}`, 'info');
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
    const poolRatio = parseFloat($val('tokenPoolRatio')) || 0;
    const distribution = $val('tokenDist');
    if (!symbol || !name || isNaN(totalSupplyBtr) || totalSupplyBtr <= 0) {
        addLog('globalLog', '全項目を入力', 'error');
        return;
    }
    const totalSupplyWei = btrToWei(totalSupplyBtr);
    await signAndSend({
        type: 'create_token', token: BTR_ADDRESS,
        data: { symbol, name, totalSupply: totalSupplyWei, poolRatio, distribution }
    });
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
    if (workerBlobURL) {
        URL.revokeObjectURL(workerBlobURL);
        workerBlobURL = null;
    }
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
    cleanupWorker();
    // ★ rewardはWei文字列 — Workerに渡すブロックデータもそのまま文字列
    const blockData = {
        height: chainHeight,
        previousHash: latestBlockHash,
        timestamp: Date.now(),
        nonce: 0,
        difficulty: currentDifficulty,
        miner: wallet.address,
        reward: latestReward, // Wei文字列のまま
        transactions: pendingTransactions,
        hash: '',
    };
    // ★ computeBlockHash はノードと完全に同じ式:
    //    sha256(previousHash + timestamp + nonce + difficulty + miner + reward + JSON.stringify(transactions))
    //    reward が Wei文字列なので文字列連結でそのまま動く
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

  onmessage = async (e) => {
    const block = e.data;
    const target = '0'.repeat(block.difficulty);
    let attempts = 0;
    const maxAttempts = 100000;

    while (attempts < maxAttempts) {
      block.nonce = Math.floor(Math.random() * 1e15);
      const hash = await computeBlockHash(block);
      attempts++;

      if (hash.startsWith(target)) {
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
    mineWorker = new Worker(workerBlobURL);
    mineWorker.onmessage = (e) => {
        totalHashes += e.data.attempts || 0;
        if (e.data.success) {
            const block = e.data.block;
            minedCount++;
            $('minedBlocks').textContent = String(minedCount);
            addLog('miningLog', `ブロック発見! nonce=${block.nonce} hash=${block.hash.slice(0, 16)}...`, 'success');
            send({ type: 'block_broadcast', data: { ...block, minerId: wallet?.address } });
            cleanupWorker();
        }
        else {
            if (isMining)
                startMineWorker();
        }
    };
    mineWorker.onerror = (err) => {
        addLog('miningLog', `Worker エラー: ${err.message}`, 'error');
        cleanupWorker();
        if (isMining)
            setTimeout(startMineWorker, 1000);
    };
    mineWorker.postMessage(blockData);
}
// ============================================================
// QRコード
// ============================================================
function showQR() {
    if (!wallet) {
        addLog('globalLog', 'ウォレットがありません', 'error');
        return;
    }
    const qrDiv = $('qrCode');
    qrDiv.innerHTML = '';
    qrDiv.style.display = 'block';
    const baseURL = window.location.origin + window.location.pathname;
    const amountStr = $val('qrAmount') || '0';
    const qrData = `${baseURL}${wallet.address}/${amountStr}`;
    if (typeof window.QRious === 'undefined') {
        qrDiv.innerHTML = `<div style="padding:20px;word-break:break-all">${qrData}</div>`;
        return;
    }
    const qr = new window.QRious({ element: document.createElement('canvas'), value: qrData, size: 200 });
    qrDiv.appendChild(qr.image);
    const urlDiv = document.createElement('div');
    urlDiv.style.cssText = 'margin-top:10px;font-size:10px;word-break:break-all;color:var(--text2)';
    urlDiv.textContent = qrData;
    qrDiv.appendChild(urlDiv);
}
function hideQR() { $('qrCode').style.display = 'none'; }
// ============================================================
// 初期化
// ============================================================
async function init() {
    await loadWallet();
    connect();
    $('btnCreate').addEventListener('click', createWallet);
    $('btnImport').addEventListener('click', importWallet);
    $('btnExport').addEventListener('click', exportWallet);
    $('btnSend').addEventListener('click', sendBTR);
    $('btnTokenSend').addEventListener('click', sendToken);
    $('btnCreateToken').addEventListener('click', createToken);
    $('btnSwap').addEventListener('click', executeSwap);
    $('btnSwapRate').addEventListener('click', requestSwapRate);
    $('btnTokenSearch').addEventListener('click', searchToken);
    $('btnMine').addEventListener('click', toggleMining);
    $('btnShowQR').addEventListener('click', showQR);
    $('btnHideQR').addEventListener('click', hideQR);
    document.querySelectorAll('nav button').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = e.target.dataset.panel;
            if (target)
                switchTab(target);
        });
    });
    $('sendAmount').addEventListener('keypress', (e) => { if (e.key === 'Enter')
        sendBTR(); });
    $('tokenSearch').addEventListener('keypress', (e) => { if (e.key === 'Enter')
        searchToken(); });
    $('swapAmount').addEventListener('keypress', (e) => { if (e.key === 'Enter')
        executeSwap(); });
    addLog('globalLog', 'クライアント起動 (BigInt版)', 'info');
}
document.addEventListener('DOMContentLoaded', init);
//# sourceMappingURL=index.js.map