// ============================================================
// BTR (Buturi Coin) - クライアント
// crypto.ts の Ed25519 を使用
// ============================================================
import { Ed25519 } from './crypto.js';
const DELIMITER = '\nLINE_BREAK\n';
const BTR_ADDRESS = '0x0000000000000000';
const GAS_FEE = 0.5;
const WS_URL = 'wss://mail.shudo-physics.com:443';
// ============================================================
// 状態
// ============================================================
let ws = null;
let wallet = null;
let balance = 0;
let tokenBalances = {};
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
            updateBalanceUI();
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
            if ((blk.difficulty || 0) > currentDifficulty) {
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
            }
            if (wallet)
                requestBalance();
            break;
        case 'rate':
            $('swapRate').textContent = `レート: 1 token = ${packet.data.rate?.toFixed(6) || '?'} BTR`;
            break;
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
    const tokenKeys = Object.keys(tokenBalances);
    if (tokenKeys.length > 0) {
        $('tokenBalances').style.display = 'block';
        $('tokenList').innerHTML = tokenKeys.map(addr => {
            const t = tokenBalances[addr];
            return `<div class="token-item"><span>${t.symbol} <span style="color:var(--text2);font-size:11px">${t.name}</span></span><span>${t.balance.toLocaleString()}</span></div>`;
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
        nonce++;
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
// ============================================================
// マイニング (Web Worker)
// ============================================================
const MINE_WORKER_CODE = `
self.onmessage = function(e) {
  const { previousHash, timestamp, miner, transactions, difficulty, startNonce } = e.data;
  const targetMax = 0xFFFFFFFF;
  const target = Math.floor(targetMax / difficulty);
  const txStr = JSON.stringify(transactions);
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
    const input=previousHash+timestamp+nonce+miner+txStr;
    const hash=sha256sync(input);
    const prefix=parseInt(hash.slice(0,8),16);
    if(prefix<=target){self.postMessage({type:'found',nonce,hash,hashCount});return;}
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
    addLog('miningLog', `掘り始め: #${block.height} diff=${currentDifficulty} prev=${latestBlockHash.slice(0, 12)}...`, 'info');
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
            addLog('miningLog', `ブロック発見! #${block.height} nonce=${e.data.nonce} hash=${e.data.hash.slice(0, 16)}...`, 'success');
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
      <label>宛先アドレス</label><input type="text" id="sendTo" placeholder="0x...">
      <label>金額 (BTR)</label><input type="number" id="sendAmount" placeholder="0" step="0.1" min="0">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">ガス代: 0.5 BTR</div>
      <button class="btn" id="btnSendBTR">送金</button>
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
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:12px">作成費: 10,000 BTR + ガス代 0.5 BTR</div>
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
    <div class="card"><h2>ログ</h2><div class="log-box" id="globalLog"></div></div>
  </div>
</main>
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
    // トークン
    $('btnCreateToken').addEventListener('click', () => createToken());
    // スワップ
    $('btnSwap').addEventListener('click', () => executeSwap());
}
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