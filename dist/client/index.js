// ============================================================
// BTR (Buturi Coin) - クライアント
// crypto.ts の Ed25519 を使用
// ============================================================
import { Ed25519 } from './crypto.js';
const DELIMITER = '\nLINE_BREAK\n';
const BTR_ADDRESS = '0x0000000000000000';
const GAS_FEE = 1;
const WS_URL = 'wss://shudo-physics.f5.si:443';
// ============================================================
// 状態
// ============================================================
let ws = null;
let wallet = null;
let balance = 0;
let tokenBalances = {};
let tokenInfoCache = {};
let miningTargetToken = ''; // 空=BTRのまま、アドレス指定=掘ったらswap
let isMining = false;
let mineWorker = null;
let minedCount = 0;
let chainHeight = 0;
let currentDifficulty = 1;
let nonce = 0;
let miningStartTime = 0;
let totalHashes = 0;
let latestBlockHash = '0'.repeat(64);
let latestReward = 100;
let pendingTransactions = [];
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
function $(id) {
    return document.getElementById(id);
}
function $val(id) {
    return document.getElementById(id).value.trim();
}
function switchTab(panelName) {
    // すべてのタブとパネルを非アクティブ化
    document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    // 指定されたタブとパネルをアクティブ化
    const targetButton = document.querySelector(`nav button[data-panel="${panelName}"]`);
    if (targetButton)
        targetButton.classList.add('active');
    const targetPanel = $(`panel-${panelName}`);
    if (targetPanel)
        targetPanel.classList.add('active');
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
    ws.onerror = () => {
        addLog('globalLog', '接続エラー', 'error');
    };
}
function send(packet) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(packet) + DELIMITER);
    }
}
// ============================================================
// パケットハンドリング
// ============================================================
function handlePacket(packet) {
    switch (packet.type) {
        case 'balance':
            balance = packet.data.balance || 0;
            tokenBalances = packet.data.tokens || {};
            nonce = packet.data.nonce || 0;
            // 未知のトークンの情報を取得
            for (const addr of Object.keys(tokenBalances)) {
                if (!tokenInfoCache[addr]) {
                    send({ type: 'get_token', data: { address: addr } });
                }
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
                // ブロックのdifficultyは「そのブロックが掘られた時の難易度」なので
                // currentDifficultyは上書きしない（get_heightやblock_acceptedから取得する）
                $('chainHeight').textContent = String(chainHeight);
                $('difficulty').textContent = String(currentDifficulty);
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
            if (blk.difficulty) {
                currentDifficulty = blk.difficulty;
            }
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            // 自分のブロックは完全無視（block_acceptedで全部やる）
            if (wallet && blk.miner === wallet.address)
                break;
            // 他人のブロック
            addLog('globalLog', `新ブロック #${blk.height} diff=${currentDifficulty} (他のマイナー)`, 'success');
            if (wallet)
                requestBalance();
            if (isMining) {
                if (mineWorker) {
                    mineWorker.terminate();
                    mineWorker = null;
                }
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
                // 失敗時はnonceを戻す（楽観インクリメントの補正）
                if (nonce > 0)
                    nonce--;
            }
            if (wallet)
                requestBalance();
            break;
        case 'rate':
            if (packet.data.rate != null) {
                const rateTokenAddr = packet.data.tokenAddress || '';
                const rateInfo = tokenInfoCache[rateTokenAddr];
                const rateLabel = rateInfo ? rateInfo.symbol : rateTokenAddr.slice(0, 10) + '...';
                $('swapRate').textContent = `レート: 1 ${rateLabel} = ${packet.data.rate.toFixed(6)} BTR`;
            }
            else {
                $('swapRate').textContent = 'レート: 取得失敗（プールなし？）';
            }
            break;
        case 'token_info': {
            const ti = packet.data?.token;
            if (ti && ti.address) {
                tokenInfoCache[ti.address] = { symbol: ti.symbol, name: ti.name };
                // UIを更新（キャッシュが埋まったタイミングで再描画）
                updateBalanceUI();
                updateMiningTokenSelect();
            }
            break;
        }
        case 'tokens_list': {
            const list = packet.data?.tokens || [];
            // キャッシュに全部入れる
            for (const t of list) {
                tokenInfoCache[t.address] = { symbol: t.symbol, name: t.name };
            }
            updateMiningTokenSelect();
            // 検索結果を表示（pending searchがあれば）
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
                latestReward = tmpl.reward || latestReward;
                pendingTransactions = tmpl.transactions || [];
                $('chainHeight').textContent = String(chainHeight);
                $('difficulty').textContent = String(currentDifficulty);
                addLog('miningLog', `テンプレート受信: height=${chainHeight} tx=${pendingTransactions.length} diff=${currentDifficulty} reward=${latestReward}`, 'info');
                // テンプレート受信 → マイニング開始
                if (isMining) {
                    startMineWorker();
                }
            }
            break;
        }
        case 'block_accepted': {
            const acc = packet.data;
            chainHeight = acc.height || chainHeight;
            latestBlockHash = acc.hash || latestBlockHash;
            currentDifficulty = acc.difficulty || currentDifficulty;
            latestReward = acc.reward || latestReward;
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            addLog('miningLog', `ブロック承認! height=${chainHeight} diff=${currentDifficulty}`, 'success');
            if (wallet)
                requestBalance();
            // 自動スワップ: トークンが選択されてたら報酬をswap
            if (miningTargetToken && wallet) {
                const swapAmount = acc.reward || latestReward;
                const info = tokenInfoCache[miningTargetToken];
                addLog('miningLog', `自動スワップ: ${swapAmount} BTR → ${info ? info.symbol : miningTargetToken.slice(0, 10) + '...'}`, 'info');
                signAndSend({
                    type: 'swap',
                    token: BTR_ADDRESS,
                    data: { tokenIn: BTR_ADDRESS, tokenOut: miningTargetToken, amountIn: swapAmount }
                });
            }
            // すぐ次を掘る
            if (isMining) {
                if (mineWorker) {
                    mineWorker.terminate();
                    mineWorker = null;
                }
                miningStartTime = Date.now();
                totalHashes = 0;
                requestBlockTemplate();
            }
            break;
        }
        case 'block_rejected': {
            const rej = packet.data;
            // 正しい難易度で上書き
            currentDifficulty = rej.difficulty || currentDifficulty;
            chainHeight = rej.height || chainHeight;
            latestBlockHash = rej.hash || latestBlockHash;
            $('chainHeight').textContent = String(chainHeight);
            $('difficulty').textContent = String(currentDifficulty);
            addLog('miningLog', `ブロック拒否: ${rej.error} → diff=${currentDifficulty}`, 'error');
            if (isMining) {
                if (mineWorker) {
                    mineWorker.terminate();
                    mineWorker = null;
                }
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
            // 新Txがmempoolに入った → マイニング中ならテンプレート再取得
            // ただし連続リスタートを防ぐためデバウンス（最後のnew_txから500ms待つ）
            if (isMining) {
                if (window.__newTxDebounce)
                    clearTimeout(window.__newTxDebounce);
                window.__newTxDebounce = setTimeout(() => {
                    if (isMining && mineWorker) {
                        mineWorker.terminate();
                        mineWorker = null;
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
function requestBalance() {
    if (!wallet)
        return;
    send({ type: 'get_balance', data: { address: wallet.address } });
}
function requestHeight() {
    send({ type: 'get_height', data: {} });
}
function requestLatestBlock() {
    // 最新1ブロックだけ取得してハッシュを得る
    send({ type: 'get_chain', data: { from: Math.max(0, chainHeight - 1), to: chainHeight } });
}
function requestBlockTemplate() {
    if (!wallet)
        return;
    send({ type: 'get_block_template', data: { miner: wallet.address } });
}
// ============================================================
// ウォレット（Ed25519 from crypto.ts）
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
        const msg = e instanceof Error ? e.message : String(e);
        addLog('globalLog', `ウォレット作成失敗: ${msg}`, 'error');
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
        const msg = e instanceof Error ? e.message : String(e);
        addLog('globalLog', `インポート失敗: ${msg}`, 'error');
    }
}
function exportWallet() {
    if (!wallet) {
        addLog('globalLog', 'ウォレットがありません', 'error');
        return;
    }
    const data = `秘密鍵: ${wallet.privateKey}\n公開鍵: ${wallet.publicKey}\nアドレス: ${wallet.address}`;
    navigator.clipboard.writeText(data).then(() => {
        addLog('globalLog', 'クリップボードにコピーしました', 'success');
    });
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
// ============================================================
// UI更新
// ============================================================
function updateWalletUI() {
    if (!wallet)
        return;
    $('myAddress').textContent = wallet.address;
    $('myPubKey').textContent = wallet.publicKey;
    $('btnCreate').textContent = 'ウォレット再作成（上書き）';
}
function updateBalanceUI() {
    $('btrBalance').textContent = balance.toLocaleString(undefined, { maximumFractionDigits: 2 });
    const tokenKeys = Object.keys(tokenBalances).filter(addr => tokenBalances[addr] > 0);
    if (tokenKeys.length > 0) {
        $('tokenBalances').style.display = 'block';
        $('tokenList').innerHTML = tokenKeys.map(addr => {
            const bal = tokenBalances[addr];
            const info = tokenInfoCache[addr];
            const label = info
                ? `${info.symbol} <span style="color:var(--text2);font-size:11px">${info.name}</span> <span style="color:var(--text2);font-size:10px;opacity:0.6">${addr.slice(0, 10)}...</span>`
                : `<span style="color:var(--text2);font-size:11px">${addr}</span>`;
            return `<div class="token-item"><span>${label}</span><span>${bal.toLocaleString()}</span></div>`;
        }).join('');
    }
    else {
        $('tokenBalances').style.display = 'none';
    }
}
// ============================================================
// トランザクション署名 & 送信
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
        fee: GAS_FEE,
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
        nonce++; // 楽観インクリメント
        addLog('globalLog', `Tx送信: ${tx.type}`, 'info');
    }
    catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        addLog('globalLog', `署名失敗: ${msg}`, 'error');
    }
}
async function sendBTR() {
    const to = $val('sendTo');
    const amount = parseFloat($val('sendAmount'));
    if (!to || isNaN(amount) || amount <= 0) {
        addLog('globalLog', '宛先と金額を入力', 'error');
        return;
    }
    await signAndSend({ type: 'transfer', token: BTR_ADDRESS, to, amount });
}
async function sendToken() {
    const token = $val('tokenSendToken');
    const to = $val('tokenSendTo');
    const amount = parseFloat($val('tokenSendAmount'));
    if (!token || !to || isNaN(amount) || amount <= 0) {
        addLog('globalLog', '全項目を入力', 'error');
        return;
    }
    await signAndSend({ type: 'token_transfer', token, to, amount });
}
async function createToken() {
    const symbol = $val('tokenSymbol');
    const name = $val('tokenName');
    const totalSupply = parseInt($val('tokenSupply'));
    const poolRatio = parseFloat($val('tokenPoolRatio')) || 0;
    const distribution = $val('tokenDist');
    if (!symbol || !name || isNaN(totalSupply) || totalSupply <= 0) {
        addLog('globalLog', '全項目を入力', 'error');
        return;
    }
    await signAndSend({ type: 'create_token', token: BTR_ADDRESS, data: { symbol, name, totalSupply, poolRatio, distribution } });
}
async function executeSwap() {
    const tokenIn = $val('swapIn') || BTR_ADDRESS;
    const tokenOut = $val('swapOut');
    const amountIn = parseFloat($val('swapAmount'));
    if (!tokenOut || isNaN(amountIn) || amountIn <= 0) {
        addLog('globalLog', '全項目を入力', 'error');
        return;
    }
    await signAndSend({ type: 'swap', token: BTR_ADDRESS, data: { tokenIn, tokenOut, amountIn } });
}
function requestSwapRate() {
    // 売る/買うどちらか非BTRのアドレスでレートを取得
    const tokenIn = $val('swapIn') || BTR_ADDRESS;
    const tokenOut = $val('swapOut');
    const tokenAddr = tokenIn !== BTR_ADDRESS ? tokenIn : tokenOut;
    if (tokenAddr && tokenAddr !== BTR_ADDRESS && tokenAddr.length > 4) {
        send({ type: 'get_rate', data: { address: tokenAddr } });
        $('swapRate').textContent = 'レート: 取得中...';
    }
}
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
    $('tokenSearchResults').innerHTML = matches.map(t => `<div class="token-item" style="flex-direction:column;gap:4px;cursor:pointer" data-addr="${t.address}">
      <div><strong style="color:var(--accent)">${t.symbol}</strong> <span style="color:var(--text2)">${t.name}</span></div>
      <div style="font-size:10px;color:var(--text2)">${t.address}　供給量: ${t.totalSupply.toLocaleString()}</div>
    </div>`).join('');
    // クリックでアドレスをコピー
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
    // BTR（デフォルト）
    let html = '<option value="">BTR（そのまま）</option>';
    // 既知トークンを追加
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
// マイニング (Web Worker)
// ============================================================
const MINE_WORKER_CODE = `
self.onmessage = function(e) {
  const { previousHash, timestamp, miner, transactions, difficulty, reward, startNonce } = e.data;
  const txStr = JSON.stringify(transactions);
  const prefix = '0'.repeat(difficulty);
  let nonce = startNonce;
  let hashCount = 0;
  function sha256sync(str) {
    const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
    const rotr=(x,n)=>(x>>>n)|(x<<(32-n));
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const data=new TextEncoder().encode(str);
    const len=data.length;const bitLen=len*8;
    const padLen=len+1+8;const blockCount=Math.ceil(padLen/64);
    const blocks=new Uint8Array(blockCount*64);blocks.set(data);blocks[len]=0x80;
    const view=new DataView(blocks.buffer);
    view.setUint32(blocks.length-8,0,false);view.setUint32(blocks.length-4,bitLen,false);
    for(let i=0;i<blocks.length;i+=64){
      const W=new Uint32Array(64);
      for(let t=0;t<16;t++)W[t]=view.getUint32(i+t*4,false);
      for(let t=16;t<64;t++){const s0=rotr(W[t-15],7)^rotr(W[t-15],18)^(W[t-15]>>>3);const s1=rotr(W[t-2],17)^rotr(W[t-2],19)^(W[t-2]>>>10);W[t]=(W[t-16]+s0+W[t-7]+s1)>>>0;}
      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for(let t=0;t<64;t++){const S1=rotr(e,6)^rotr(e,11)^rotr(e,25);const ch=(e&f)^(~e&g);const t1=(h+S1+ch+K[t]+W[t])>>>0;const S0=rotr(a,2)^rotr(a,13)^rotr(a,22);const maj=(a&b)^(a&c)^(b&c);const t2=(S0+maj)>>>0;h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
      h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
    }
    return[h0,h1,h2,h3,h4,h5,h6,h7].map(x=>x.toString(16).padStart(8,'0')).join('');
  }
  while(true){
    const input=previousHash+timestamp+nonce+difficulty+miner+reward+txStr;
    const hash=sha256sync(input);
    if(hash.startsWith(prefix)){self.postMessage({type:'found',nonce,hash,hashCount});return;}
    nonce++;hashCount++;
    if(hashCount%5000===0)self.postMessage({type:'progress',hashCount,nonce});
  }
};
`;
function toggleMining() {
    if (isMining)
        stopMining();
    else
        startMining();
}
function startMining() {
    if (!wallet) {
        addLog('miningLog', 'ウォレットを先に作成してください', 'error');
        return;
    }
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        addLog('miningLog', '接続されていません', 'error');
        return;
    }
    isMining = true;
    miningStartTime = Date.now();
    totalHashes = 0;
    $('btnMine').textContent = 'マイニング停止';
    $('btnMine').classList.add('danger');
    $('miningStatus').textContent = '稼働中';
    $('miningStatus').style.color = 'var(--accent)';
    addLog('miningLog', 'マイニング開始', 'success');
    requestBlockTemplate();
}
function stopMining() {
    isMining = false;
    if (mineWorker) {
        mineWorker.terminate();
        mineWorker = null;
    }
    $('btnMine').textContent = 'マイニング開始';
    $('btnMine').classList.remove('danger');
    $('miningStatus').textContent = '停止中';
    $('miningStatus').style.color = '';
    addLog('miningLog', 'マイニング停止', 'info');
}
function startMineWorker() {
    if (!isMining || !wallet)
        return;
    if (mineWorker) {
        mineWorker.terminate();
        mineWorker = null;
    }
    const block = {
        height: chainHeight,
        previousHash: latestBlockHash,
        timestamp: Date.now(),
        difficulty: currentDifficulty || 1,
        miner: wallet.address,
        reward: latestReward,
        transactions: pendingTransactions,
    };
    addLog('miningLog', `掘り始め: #${block.height} diff=${currentDifficulty} tx=${block.transactions.length} prev=${latestBlockHash.slice(0, 12)}...`, 'info');
    const blob = new Blob([MINE_WORKER_CODE], { type: 'application/javascript' });
    const url = URL.createObjectURL(blob);
    mineWorker = new Worker(url);
    mineWorker.onmessage = (e) => {
        if (e.data.type === 'progress') {
            totalHashes = e.data.hashCount;
            const elapsed = (Date.now() - miningStartTime) / 1000;
            const rate = Math.floor(totalHashes / elapsed);
            $('hashrate').textContent = rate.toLocaleString() + ' H/s';
        }
        else if (e.data.type === 'found') {
            const minedBlock = { ...block, nonce: e.data.nonce, hash: e.data.hash };
            addLog('miningLog', `ブロック発見! #${block.height} nonce=${e.data.nonce} tx=${block.transactions.length} hash=${e.data.hash.slice(0, 16)}...`, 'success');
            minedCount++;
            $('minedBlocks').textContent = String(minedCount);
            latestBlockHash = e.data.hash;
            chainHeight++;
            send({ type: 'mine', data: minedBlock });
            URL.revokeObjectURL(url);
            mineWorker = null; // Worker終了を明示
            addLog('miningLog', 'block_accepted待ち...', 'info');
            // block_accepted が来たら startMineWorker が呼ばれる
        }
    };
    mineWorker.postMessage({
        previousHash: block.previousHash,
        timestamp: block.timestamp,
        miner: block.miner,
        transactions: block.transactions,
        difficulty: block.difficulty,
        reward: block.reward,
        startNonce: 0,
    });
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
    <div class="card"><h2>残高</h2><div class="balance-display"><span id="btrBalance">0</span> <span>BTR</span></div></div>
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
      <label>宛先アドレス</label>
      <div style="display:flex;gap:8px;margin-bottom:12px">
        <input type="text" id="sendTo" placeholder="0x..." style="flex:1;margin-bottom:0">
        <button class="btn secondary" onclick="scanQR()" style="width:auto;padding:10px 16px">QR</button>
      </div>
      <label>金額 (BTR)</label><input type="number" id="sendAmount" placeholder="0" step="0.1" min="0">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">ガス代: 1 BTR</div>
      <button class="btn" id="btnSendBTR">送金</button>
    </div>
    <div class="card"><h2>受取用QRコード</h2>
      <label>金額指定（任意）</label><input type="number" id="receiveAmount" placeholder="金額を指定しない場合は空欄" step="0.1" min="0">
      <button class="btn secondary" onclick="showReceiveQR()">QRコード生成</button>
    </div>
    <div class="card"><h2>トークン送金</h2>
      <label>トークンアドレス</label><input type="text" id="tokenSendToken" placeholder="0x...">
      <label>宛先アドレス</label><input type="text" id="tokenSendTo" placeholder="0x...">
      <label>金額</label><input type="number" id="tokenSendAmount" placeholder="0" step="0.1" min="0">
      <button class="btn" id="btnSendToken">送金</button>
    </div>
  </div>

  <div class="panel" id="panel-mining">
    <div class="card"><h2>マイニング</h2>
      <div class="mining-stats">
        <div class="stat-box"><div class="label">ステータス</div><div class="value" id="miningStatus">停止中</div></div>
        <div class="stat-box"><div class="label">ハッシュレート</div><div class="value hashrate" id="hashrate">0 H/s</div></div>
        <div class="stat-box"><div class="label">難易度</div><div class="value" id="difficulty">-</div></div>
        <div class="stat-box"><div class="label">採掘ブロック</div><div class="value" id="minedBlocks">0</div></div>
      </div>
      <label>報酬の受け取り方</label>
      <select id="miningTarget">
        <option value="">BTR（そのまま）</option>
      </select>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">トークンを選ぶと、ブロック報酬を自動でスワップします</div>
      <button class="btn" id="btnMine">マイニング開始</button>
    </div>
    <div class="card"><h2>ログ</h2><div class="log-box" id="miningLog"></div></div>
  </div>

  <div class="panel" id="panel-tokens">
    <div class="card"><h2>トークン作成</h2>
      <label>シンボル</label><input type="text" id="tokenSymbol" placeholder="PHY" maxlength="10">
      <label>名前</label><input type="text" id="tokenName" placeholder="PhysicsCoin">
      <label>総供給量</label><input type="number" id="tokenSupply" placeholder="1000000" min="1">
      <label>AMMプール比率 (0〜1)</label><input type="number" id="tokenPoolRatio" placeholder="0.5" step="0.1" min="0" max="1">
      <label>配布方式</label>
      <select id="tokenDist"><option value="creator">全額作成者に渡る</option><option value="mining">マイニングで徐々に発行</option><option value="split">作成者とプールに分配</option><option value="airdrop">接続中のウォレットに均等配布</option></select>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">作成費: 10,000 BTR + ガス代 1 BTR</div>
      <button class="btn" id="btnCreateToken">トークン作成</button>
    </div>
  </div>

  <div class="panel" id="panel-swap">
    <div class="card"><h2>スワップ (AMM)</h2>
      <label>売るトークン</label><input type="text" id="swapIn" placeholder="0x0000000000000000 (BTR)">
      <label>買うトークン</label><input type="text" id="swapOut" placeholder="トークンアドレス">
      <label>金額</label><input type="number" id="swapAmount" placeholder="0" step="0.1" min="0">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px" id="swapRate">レート: -</div>
      <button class="btn" id="btnSwap">スワップ</button>
    </div>
  </div>

  <div class="panel" id="panel-explorer">
    <div class="card"><h2>チェーン情報</h2>
      <div class="mining-stats">
        <div class="stat-box"><div class="label">ブロック高さ</div><div class="value" id="chainHeight">-</div></div>
        <div class="stat-box"><div class="label">接続ノード</div><div class="value" id="nodeCount">-</div></div>
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

<!-- QRコード表示モーダル -->
<div id="qrCodeContainer" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);z-index:1000;justify-content:center;align-items:center">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:32px;max-width:400px;width:90%;position:relative">
    <button onclick="closeQRCode()" style="position:absolute;top:12px;right:12px;background:none;border:none;color:var(--text);font-size:24px;cursor:pointer;padding:8px">×</button>
    <h2 style="font-family:var(--mono);font-size:18px;color:var(--accent);margin-bottom:20px;text-align:center">受取用QRコード</h2>
    <div id="qrCanvas" style="display:flex;justify-content:center;margin-bottom:20px;min-height:256px;align-items:center"></div>
    <div id="qrInfo" style="font-family:var(--mono);font-size:12px;color:var(--text2);line-height:1.8"></div>
  </div>
</div>

<!-- QRスキャナーモーダル -->
<div id="qrScannerContainer" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.95);z-index:1000">
  <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:90%;max-width:500px">
    <button onclick="closeQRScanner()" style="position:absolute;top:-40px;right:0;background:none;border:none;color:white;font-size:32px;cursor:pointer;padding:8px">×</button>
    <video id="qrVideo" style="width:100%;border-radius:12px;border:2px solid var(--accent)"></video>
    <div style="text-align:center;color:white;font-family:var(--mono);font-size:14px;margin-top:16px">QRコードをカメラに映してください</div>
  </div>
</div>

<script>
// 軽量QRコード生成ライブラリ（インライン）
var qrcode=function(){var t=function(t,e){var n=t,r=QRErrorCorrectLevel[e],o={},i=0,a=[],u=0,l={},c=function(t,e){u=4*n+17,o=function(t){for(var e=new Array(t),n=0;n<t;n+=1){e[n]=new Array(t);for(var r=0;r<t;r+=1)e[n][r]=null}return e}(u),s(0,0),s(u-7,0),s(0,u-7),g(),h(),v(t,e),n>=7&&f(t),null==l&&(l=m(n,r,a)),p(l,e)},s=function(t,e){for(var n=-1;n<=7;n+=1)if(!(t+n<=-1||u<=t+n))for(var r=-1;r<=7;r+=1)e+r<=-1||u<=e+r||(o[t+n][e+r]=0<=n&&n<=6&&(0==r||6==r)||0<=r&&r<=6&&(0==n||6==n)||2<=n&&n<=4&&2<=r&&r<=4)},g=function(){for(var t=8;t<u-8;t+=1)null==o[t][6]&&(o[t][6]=t%2==0);for(var e=8;e<u-8;e+=1)null==o[6][e]&&(o[6][e]=e%2==0)},h=function(){for(var t=QRUtil.getPatternPosition(n),e=0;e<t.length;e+=1)for(var r=0;r<t.length;r+=1){var i=t[e],a=t[r];if(null==o[i][a])for(var u=-2;u<=2;u+=1)for(var l=-2;l<=2;l+=1)o[i+u][a+l]=-2==u||2==u||-2==l||2==l||0==u&&0==l}},v=function(t,e){for(var n=QRUtil.getBCHTypeInfo(r<<3|e),i=0;i<15;i+=1){var a=!t&&1==(n>>i&1);i<6?o[i][8]=a:i<8?o[i+1][8]=a:o[u-15+i][8]=a}for(i=0;i<15;i+=1){a=!t&&1==(n>>i&1);i<8?o[8][u-i-1]=a:i<9?o[8][15-i-1+1]=a:o[8][15-i-1]=a}o[u-8][8]=!t},f=function(t){for(var e=QRUtil.getBCHTypeNumber(n),r=0;r<18;r+=1){var i=!t&&1==(e>>r&1);o[Math.floor(r/3)][r%3+u-8-3]=i}for(r=0;r<18;r+=1){i=!t&&1==(e>>r&1);o[r%3+u-8-3][Math.floor(r/3)]=i}},p=function(t,e){for(var n=-1,r=u-1,i=7,a=0,l=QRUtil.getMaskFunction(e),c=u-1;c>0;c-=2)for(6==c&&(c-=1);;){for(var s=0;s<2;s+=1)if(null==o[r][c-s]){var g=!1;a<t.length&&(g=1==(t[a]>>>i&1)),l(r,c-s)&&(g=!g),o[r][c-s]=g,-1==--i&&(a+=1,i=7)}if((r+=n)<0||u<=r){r-=n,n=-n;break}}},m=function(t,e,n){for(var r=QRPolynomial.getRSBlocks(t,e),o=QRBitBuffer(),i=0;i<n.length;i+=1){var a=n[i];o.put(a.getMode(),4),o.put(a.getLength(),QRUtil.getLengthInBits(a.getMode(),t)),a.write(o)}for(var u=0,i=0;i<r.length;i+=1)u+=r[i].dataCount;if(o.getLengthInBits()>8*u)throw new Error("code length overflow. ("+o.getLengthInBits()+">"+8*u+")");for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return d(o,r)},d=function(t,e){for(var n=0,r=0,o=0,i=new Array(e.length),a=new Array(e.length),u=0;u<e.length;u+=1){var l=e[u].dataCount,c=e[u].totalCount-l;r=Math.max(r,l),o=Math.max(o,c),i[u]=new Array(l);for(var s=0;s<i[u].length;s+=1)i[u][s]=255&t.getBuffer()[s+n];n+=l;var g=QRUtil.getErrorCorrectPolynomial(c),h=QRPolynomial(i[u],g.getLength()-1).mod(g);a[u]=new Array(g.getLength()-1);for(s=0;s<a[u].length;s+=1){var v=s+h.getLength()-a[u].length;a[u][s]=v>=0?h.getAt(v):0}}for(var f=0,s=0;s<e.length;s+=1)f+=e[s].totalCount;for(var p=new Array(f),m=0,s=0;s<r;s+=1)for(u=0;u<e.length;u+=1)s<i[u].length&&(p[m]=i[u][s],m+=1);for(s=0;s<o;s+=1)for(u=0;u<e.length;u+=1)s<a[u].length&&(p[m]=a[u][s],m+=1);return p};return l.addData=function(t){a.push(function(t){return{getMode:function(){return QRMode.MODE_8BIT_BYTE},getLength:function(e){return t.length},write:function(e){for(var n=0;n<t.length;n+=1)e.put(t.charCodeAt(n),8)}}}(t)),l=null},l.isDark=function(t,e){if(t<0||u<=t||e<0||u<=e)throw new Error(t+","+e);return o[t][e]},l.getModuleCount=function(){return u},l.make=function(){c(!1,function(){for(var t=0,e=0,o=0;o<8;o+=1){c(!0,o);var i=QRUtil.getLostPoint(l);(0==o||t>i)&&(t=i,e=o)}return e}())},l.createTableTag=function(t,e){t=t||2;var n="";n+='<table style="',n+=" border-width: 0px; border-style: none;",n+=" border-collapse: collapse;",n+=" padding: 0px; margin: "+(e=void 0===e?4*t:e)+"px;",n+='">',n+="<tbody>";for(var r=0;r<l.getModuleCount();r+=1){n+="<tr>";for(var o=0;o<l.getModuleCount();o+=1)n+='<td style="',n+=" border-width: 0px; border-style: none;",n+=" border-collapse: collapse;",n+=" padding: 0px; margin: 0px;",n+=" width: "+t+"px;",n+=" height: "+t+"px;",n+=" background-color: ",n+=l.isDark(r,o)?"#000000":"#ffffff",n+=";",n+='"/>';n+="</tr>"}return n+="</tbody>",n+="</table>"},l.createSvgTag=function(t,e){t=t||2,e=void 0===e?4*t:e;var n,r,o,i,a=l.getModuleCount()*t+2*e,u="";for(i="l"+t+",0 0,"+t+" -"+t+",0 ",n=0;n<l.getModuleCount();n+=1)for(o=n*t+e,r=0;r<l.getModuleCount();r+=1)l.isDark(n,r)&&(u+="M"+(r*t+e)+","+o+i);return'<svg version="1.1" xmlns="http://www.w3.org/2000/svg" width="'+a+'px" height="'+a+'px" viewBox="0 0 '+a+" "+a+'" preserveAspectRatio="none"><path d="'+u+'" stroke="transparent" fill="black"/></svg>'},l.createImgTag=function(t,e){t=t||2,e=void 0===e?4*t:e;var n=l.getModuleCount()*t+2*e,r=e,o=n-e;return function(t,e,n){var r=document.createElement("canvas");r.width=t,r.height=t;for(var o=r.getContext("2d"),i=0;i<l.getModuleCount();i+=1)for(var a=0;a<l.getModuleCount();a+=1)o.fillStyle=l.isDark(i,a)?"black":"white",o.fillRect(a*e+n,i*e+n,e,e);return r}(n,t,e).toDataURL("image/png")},l},QRMode={MODE_NUMBER:1,MODE_ALPHA_NUM:2,MODE_8BIT_BYTE:4,MODE_KANJI:8},QRErrorCorrectLevel={L:1,M:0,Q:3,H:2},QRMaskPattern={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7},QRUtil=function(){var t=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]];return{getBCHTypeInfo:function(t){for(var e=t<<10;QRUtil.getBCHDigit(e)-QRUtil.getBCHDigit(1335)>=0;)e^=1335<<QRUtil.getBCHDigit(e)-QRUtil.getBCHDigit(1335);return(t<<10|e)^21522},getBCHTypeNumber:function(t){for(var e=t<<12;QRUtil.getBCHDigit(e)-QRUtil.getBCHDigit(7973)>=0;)e^=7973<<QRUtil.getBCHDigit(e)-QRUtil.getBCHDigit(7973);return t<<12|e},getBCHDigit:function(t){for(var e=0;0!=t;)e+=1,t>>>=1;return e},getPatternPosition:function(e){return t[e-1]},getMask:function(t,e,n){switch(t){case QRMaskPattern.PATTERN000:return(e+n)%2==0;case QRMaskPattern.PATTERN001:return e%2==0;case QRMaskPattern.PATTERN010:return n%3==0;case QRMaskPattern.PATTERN011:return(e+n)%3==0;case QRMaskPattern.PATTERN100:return(Math.floor(e/2)+Math.floor(n/3))%2==0;case QRMaskPattern.PATTERN101:return e*n%2+e*n%3==0;case QRMaskPattern.PATTERN110:return(e*n%2+e*n%3)%2==0;case QRMaskPattern.PATTERN111:return(e*n%3+(e+n)%2)%2==0;default:throw new Error("bad maskPattern:"+t)}},getErrorCorrectPolynomial:function(t){for(var e=QRPolynomial([1],0),n=0;n<t;n+=1)e=e.multiply(QRPolynomial([1,QRMath.gexp(n)],0));return e},getLengthInBits:function(t,e){if(1<=e&&e<10)switch(t){case QRMode.MODE_NUMBER:return 10;case QRMode.MODE_ALPHA_NUM:return 9;case QRMode.MODE_8BIT_BYTE:case QRMode.MODE_KANJI:return 8;default:throw new Error("mode:"+t)}else if(e<27)switch(t){case QRMode.MODE_NUMBER:return 12;case QRMode.MODE_ALPHA_NUM:return 11;case QRMode.MODE_8BIT_BYTE:return 16;case QRMode.MODE_KANJI:return 10;default:throw new Error("mode:"+t)}else{if(!(e<41))throw new Error("type:"+e);switch(t){case QRMode.MODE_NUMBER:return 14;case QRMode.MODE_ALPHA_NUM:return 13;case QRMode.MODE_8BIT_BYTE:return 16;case QRMode.MODE_KANJI:return 12;default:throw new Error("mode:"+t)}}},getLostPoint:function(t){for(var e=t.getModuleCount(),n=0,r=0;r<e;r+=1)for(var o=0;o<e;o+=1){for(var i=0,a=t.isDark(r,o),u=-1;u<=1;u+=1)if(!(r+u<0||e<=r+u))for(var l=-1;l<=1;l+=1)o+l<0||e<=o+l||0==u&&0==l||a==t.isDark(r+u,o+l)&&(i+=1);i>5&&(n+=3+i-5)}for(r=0;r<e-1;r+=1)for(o=0;o<e-1;o+=1){var c=0;t.isDark(r,o)&&(c+=1),t.isDark(r+1,o)&&(c+=1),t.isDark(r,o+1)&&(c+=1),t.isDark(r+1,o+1)&&(c+=1),0!=c&&4!=c||(n+=3)}for(r=0;r<e;r+=1)for(o=0;o<e-6;o+=1)t.isDark(r,o)&&!t.isDark(r,o+1)&&t.isDark(r,o+2)&&t.isDark(r,o+3)&&t.isDark(r,o+4)&&!t.isDark(r,o+5)&&t.isDark(r,o+6)&&(n+=40);for(o=0;o<e;o+=1)for(r=0;r<e-6;r+=1)t.isDark(r,o)&&!t.isDark(r+1,o)&&t.isDark(r+2,o)&&t.isDark(r+3,o)&&t.isDark(r+4,o)&&!t.isDark(r+5,o)&&t.isDark(r+6,o)&&(n+=40);for(var s=0,o=0;o<e;o+=1)for(r=0;r<e;r+=1)t.isDark(r,o)&&(s+=1);return n+=10*(Math.abs(100*s/e/e-50)/5)},getMaskFunction:function(t){switch(t){case QRMaskPattern.PATTERN000:return function(t,e){return(t+e)%2==0};case QRMaskPattern.PATTERN001:return function(t,e){return t%2==0};case QRMaskPattern.PATTERN010:return function(t,e){return e%3==0};case QRMaskPattern.PATTERN011:return function(t,e){return(t+e)%3==0};case QRMaskPattern.PATTERN100:return function(t,e){return(Math.floor(t/2)+Math.floor(e/3))%2==0};case QRMaskPattern.PATTERN101:return function(t,e){return t*e%2+t*e%3==0};case QRMaskPattern.PATTERN110:return function(t,e){return(t*e%2+t*e%3)%2==0};case QRMaskPattern.PATTERN111:return function(t,e){return(t*e%3+(t+e)%2)%2==0};default:throw new Error("bad maskPattern:"+t)}}}}(),QRPolynomial=function(t,e){if(void 0===t.length)throw new Error(t.length+"/"+e);var n=function(){for(var n=0;n<t.length&&0==t[n];)n+=1;for(var r=new Array(t.length-n+e),o=0;o<t.length-n;o+=1)r[o]=t[o+n];return r}(),r={};return r.getAt=function(t){return n[t]},r.getLength=function(){return n.length},r.multiply=function(t){for(var e=new Array(r.getLength()+t.getLength()-1),n=0;n<r.getLength();n+=1)for(var o=0;o<t.getLength();o+=1)e[n+o]^=QRMath.gexp(QRMath.glog(r.getAt(n))+QRMath.glog(t.getAt(o)));return QRPolynomial(e,0)},r.mod=function(t){if(r.getLength()-t.getLength()<0)return r;for(var e=QRMath.glog(r.getAt(0))-QRMath.glog(t.getAt(0)),n=new Array(r.getLength()),o=0;o<r.getLength();o+=1)n[o]=r.getAt(o);for(o=0;o<t.getLength();o+=1)n[o]^=QRMath.gexp(QRMath.glog(t.getAt(o))+e);return QRPolynomial(n,0).mod(t)},r},QRMath=function(){for(var t=new Array(256),e=new Array(256),n=0;n<8;n+=1)t[n]=1<<n;for(n=8;n<256;n+=1)t[n]=t[n-4]^t[n-5]^t[n-6]^t[n-8];for(n=0;n<255;n+=1)e[t[n]]=n;return{glog:function(t){if(t<1)throw new Error("glog("+t+")");return e[t]},gexp:function(e){for(;e<0;)e+=255;for(;e>=256;)e-=255;return t[e]}}}();function QRBitBuffer(){var t=[],e=0,n={};return n.getBuffer=function(){return t},n.getAt=function(e){return 1==(t[Math.floor(e/8)]>>>7-e%8&1)},n.put=function(t,e){for(var r=0;r<e;r+=1)n.putBit(1==(t>>>e-r-1&1))},n.getLengthInBits=function(){return e},n.putBit=function(n){var r=Math.floor(e/8);t.length<=r&&t.push(0),n&&(t[r]|=128>>>e%8),e+=1},n}QRPolynomial.getRSBlocks=function(t,e){var n=function(t,e){switch(e){case QRErrorCorrectLevel.L:return[[1,26,19],[1,44,34],[1,70,55],[1,100,80],[1,134,108],[2,86,68],[2,98,78],[2,121,97],[2,146,116],[2,86,68,2,87,69],[4,101,81],[2,116,92,2,117,93],[4,133,107],[3,145,115,1,146,116],[5,109,87,1,110,88],[5,122,98,1,123,99],[7,118,94,2,119,95],[10,113,91],[9,104,84,3,105,85],[3,136,108,8,137,109],[3,127,101,10,128,102],[7,122,98,7,123,99],[5,154,122,10,155,123],[13,115,93,3,116,94],[17,115,93],[17,115,93,1,116,94],[13,132,106,6,133,107],[12,151,121,7,152,122],[6,146,116,14,147,117],[17,132,106,4,133,107],[4,154,122,18,155,123],[20,117,95,4,118,96],[19,118,96,6,119,97],[14,146,116,11,147,117],[22,121,97,3,122,98],[8,152,122,26,153,123],[12,147,117,28,148,118],[27,120,96,8,121,97],[28,113,91,14,114,92],[20,135,107,32,136,108]];case QRErrorCorrectLevel.M:return[[1,26,16],[1,44,28],[1,70,44],[2,50,32],[2,68,43],[4,62,27],[4,84,48],[2,106,60,2,107,61],[3,129,74,2,130,75],[4,97,57,1,98,58],[1,116,64,4,117,65],[6,108,65,2,109,66],[8,120,73,1,121,74],[4,154,95,5,155,96],[5,139,87,5,140,88],[7,133,81,3,134,82],[13,122,74,1,123,75],[17,98,54,1,99,55],[2,139,87,13,140,88],[17,120,73],[3,151,91,13,152,92],[21,115,69,1,116,70],[19,117,71,4,118,72],[2,163,99,17,164,100],[10,149,87,10,150,88],[14,139,83,4,140,84],[14,151,91,21,152,92],[29,119,71,7,120,72],[13,154,92,22,155,93],[40,119,71,7,120,72],[18,147,87,31,148,88],[34,118,70,34,119,71],[20,146,86,38,147,87],[35,118,70,39,119,71]];case QRErrorCorrectLevel.Q:return[[1,26,13],[1,44,22],[2,35,17],[2,50,24],[4,43,15],[2,64,29,2,65,30],[4,77,35,1,78,36],[4,96,46,2,97,47],[2,127,58,4,128,59],[6,97,43,2,98,44],[8,100,44,2,101,45],[10,98,43,2,99,44],[8,122,54,2,123,55],[3,151,78,8,152,79],[7,139,65,4,140,66],[5,151,73,7,152,74],[11,132,61,5,133,62],[5,177,85,13,178,86],[15,132,61,5,133,62],[1,151,72,17,152,73],[17,132,60,4,133,61],[2,177,85,17,178,86],[9,151,72,16,152,73],[9,151,72,29,152,73],[15,141,64,23,142,65],[19,143,65,26,144,66],[34,132,60,31,133,61],[16,161,77,41,162,78],[39,132,60,29,133,61]];case QRErrorCorrectLevel.H:return[[1,26,9],[1,44,16],[2,35,13],[4,40,9],[4,40,9,1,41,10],[4,58,16,2,59,17],[4,69,22,2,70,23],[4,81,26,2,82,27],[2,116,42,4,117,43],[6,86,28,2,87,29],[4,114,38,6,115,39],[7,100,31,4,101,32],[4,121,38,8,122,39],[5,146,47,13,147,48],[11,122,38,5,123,39],[15,112,35,5,113,36],[12,121,38,7,122,39],[15,141,44,10,142,45],[19,118,35,10,119,36],[23,116,35,3,117,36],[2,145,43,34,146,44],[10,151,45,23,152,46],[19,141,42,15,142,43],[22,135,40,20,136,41],[33,117,35,12,118,36],[12,151,45,28,152,46],[11,141,42,41,142,43],[30,135,40,31,136,41],[20,147,44,61,148,45],[29,135,40,42,136,41]];default:return}}(t,e);if(void 0===n)throw new Error("bad rs block @ typeNumber:"+t+"/errorCorrectLevel:"+e);for(var r=n.length/3,o=[],i=0;i<r;i+=1)for(var a=n[3*i+0],u=n[3*i+1],l=n[3*i+2],c=0;c<a;c+=1)o.push({totalCount:u,dataCount:l});return o};return t}();window.qrcode=qrcode;
</script>
<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js"></script>
`;
}
// ============================================================
// イベントバインド
// ============================================================
function bindEvents() {
    // ナビ
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
    // ウォレット
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
    // 送金
    $('btnSendBTR').addEventListener('click', () => sendBTR());
    $('btnSendToken').addEventListener('click', () => sendToken());
    // マイニング
    $('btnMine').addEventListener('click', () => toggleMining());
    $('miningTarget').addEventListener('change', () => {
        miningTargetToken = $('miningTarget').value;
        const info = tokenInfoCache[miningTargetToken];
        if (miningTargetToken) {
            addLog('miningLog', `報酬先: ${info ? info.symbol : miningTargetToken.slice(0, 10) + '...'}に自動スワップ`, 'info');
        }
        else {
            addLog('miningLog', '報酬先: BTR（そのまま）', 'info');
        }
    });
    // トークン
    $('btnCreateToken').addEventListener('click', () => createToken());
    // スワップ
    $('btnSwap').addEventListener('click', () => executeSwap());
    // トークン検索
    $('btnTokenSearch').addEventListener('click', () => searchToken());
    $('tokenSearch').addEventListener('keydown', (e) => {
        if (e.key === 'Enter')
            searchToken();
    });
    // スワップ入力変更時にレート取得
    $('swapOut').addEventListener('change', () => requestSwapRate());
    $('swapOut').addEventListener('input', () => {
        if (window.__rateDebounce)
            clearTimeout(window.__rateDebounce);
        window.__rateDebounce = setTimeout(requestSwapRate, 500);
    });
    $('swapIn').addEventListener('change', () => requestSwapRate());
    $('swapIn').addEventListener('input', () => {
        if (window.__rateDebounce)
            clearTimeout(window.__rateDebounce);
        window.__rateDebounce = setTimeout(requestSwapRate, 500);
    });
}
// ============================================================
// QRコード機能
// ============================================================
// QRコード生成
function generateQRCode(address, amount, token) {
    const qrContainer = $('qrCodeContainer');
    const qrCanvas = $('qrCanvas');
    // QR用データ構築（btr:// URIスキーム）
    let qrData = `btr://${address}`;
    const params = [];
    if (amount)
        params.push(`amount=${amount}`);
    if (token && token !== BTR_ADDRESS)
        params.push(`token=${token}`);
    if (params.length > 0)
        qrData += `?${params.join('&')}`;
    // canvas要素作成
    qrCanvas.innerHTML = '';
    try {
        // qrcode-generatorを使用
        if (typeof window.qrcode !== 'undefined') {
            const typeNumber = 0; // 自動サイズ
            const errorCorrectionLevel = 'H';
            const qr = window.qrcode(typeNumber, errorCorrectionLevel);
            qr.addData(qrData);
            qr.make();
            // SVGで描画（確実）
            const cellSize = 4;
            const moduleCount = qr.getModuleCount();
            const svgSize = moduleCount * cellSize + 32; // パディング含む
            let svg = `<svg width="${svgSize}" height="${svgSize}" viewBox="0 0 ${svgSize} ${svgSize}" xmlns="http://www.w3.org/2000/svg">`;
            svg += `<rect width="${svgSize}" height="${svgSize}" fill="white"/>`;
            const offset = 16; // パディング
            for (let row = 0; row < moduleCount; row++) {
                for (let col = 0; col < moduleCount; col++) {
                    if (qr.isDark(row, col)) {
                        svg += `<rect x="${offset + col * cellSize}" y="${offset + row * cellSize}" width="${cellSize}" height="${cellSize}" fill="black"/>`;
                    }
                }
            }
            svg += '</svg>';
            const container = document.createElement('div');
            container.style.border = '8px solid white';
            container.style.borderRadius = '8px';
            container.style.display = 'inline-block';
            container.innerHTML = svg;
            qrCanvas.appendChild(container);
        }
        else {
            throw new Error('QRコードライブラリ未読み込み');
        }
    }
    catch (e) {
        // フォールバック: テキスト表示
        qrCanvas.innerHTML = `<div style="padding:40px;text-align:center;border:2px dashed var(--border);border-radius:8px">
      <div style="font-size:14px;color:var(--text);margin-bottom:8px">QRコード生成エラー</div>
      <div style="font-size:11px;color:var(--red);margin-bottom:12px">${e.message}</div>
      <div style="font-size:11px;color:var(--text2);word-break:break-all">${qrData}</div>
    </div>`;
    }
    // QR情報表示
    $('qrInfo').innerHTML = `
    <div><strong>アドレス:</strong> ${address}</div>
    ${amount ? `<div><strong>金額:</strong> ${amount} ${token === BTR_ADDRESS || !token ? 'BTR' : 'トークン'}</div>` : ''}
    ${token && token !== BTR_ADDRESS ? `<div><strong>トークン:</strong> ${token}</div>` : ''}
    <div style="margin-top:12px;padding:8px;background:var(--bg);border-radius:4px;word-break:break-all;font-size:11px;color:var(--text2)">${qrData}</div>
  `;
    qrContainer.style.display = 'flex';
    addLog('QRコード生成完了', 'success');
}
// 受取用QRコード生成
window.showReceiveQR = function () {
    if (!wallet) {
        addLog('ウォレットが必要です', 'error');
        return;
    }
    const amountInput = $('receiveAmount');
    const amount = parseFloat(amountInput.value) || 0;
    generateQRCode(wallet.address, amount > 0 ? amount : undefined);
};
// QRコードスキャン
window.scanQR = function () {
    const videoContainer = $('qrScannerContainer');
    const video = $('qrVideo');
    // カメラ起動
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
        .then(stream => {
        video.srcObject = stream;
        video.play();
        videoContainer.style.display = 'block';
        // QRコードスキャン開始
        scanQRFromVideo(video, stream);
    })
        .catch(err => {
        addLog('カメラアクセス失敗: ' + err.message, 'error');
    });
};
function scanQRFromVideo(video, stream) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const scan = () => {
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            ctx.drawImage(video, 0, 0);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            // jsQRライブラリを使用
            if (typeof window.jsQR !== 'undefined') {
                const code = window.jsQR(imageData.data, imageData.width, imageData.height);
                if (code && code.data) {
                    // QRコード検出
                    handleQRData(code.data);
                    // カメラ停止
                    stream.getTracks().forEach(track => track.stop());
                    $('qrScannerContainer').style.display = 'none';
                    return;
                }
            }
        }
        requestAnimationFrame(scan);
    };
    scan();
}
function handleQRData(data) {
    addLog('QRコード読み取り: ' + data, 'info');
    // btr:// 形式のパース
    if (data.startsWith('btr://')) {
        try {
            const url = new URL(data);
            const address = url.hostname || url.pathname.replace('//', '');
            const amount = url.searchParams.get('amount');
            const token = url.searchParams.get('token');
            // 送金フォームに自動入力
            $('sendTo').value = address;
            if (amount)
                $('sendAmount').value = amount;
            if (token)
                $('sendToken').value = token;
            addLog(`送金情報を入力しました: ${address.slice(0, 10)}...`, 'success');
            // 送金タブに切り替え
            switchTab('send');
        }
        catch (e) {
            addLog('QRコード解析エラー: ' + e.message, 'error');
        }
    }
    else {
        // 通常のアドレス（0x...）
        $('sendTo').value = data;
        addLog('アドレスを入力しました', 'success');
        switchTab('send');
    }
}
window.closeQRScanner = function () {
    const video = $('qrVideo');
    if (video.srcObject) {
        video.srcObject.getTracks().forEach(track => track.stop());
    }
    $('qrScannerContainer').style.display = 'none';
};
window.closeQRCode = function () {
    $('qrCodeContainer').style.display = 'none';
};
// ============================================================
// フォント読み込み
// ============================================================
function loadFonts() {
    const link = document.createElement('link');
    link.href = 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap';
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
    setInterval(() => {
        if (wallet && ws && ws.readyState === WebSocket.OPEN) {
            requestBalance();
            requestHeight();
            requestLatestBlock();
        }
    }, 15000);
}
init();
//# sourceMappingURL=index.js.map