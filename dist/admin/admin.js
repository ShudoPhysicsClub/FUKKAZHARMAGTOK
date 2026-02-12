// ============================================================
// BTR (Buturi Coin) - 管理者パネル クライアント
// ============================================================
import { Ed25519 } from '../client/crypto.js';
const DELIMITER = '\nLINE_BREAK\n';
const WS_URL = 'wss://shudo-physics.f5.si:443';
// ============================================================
// 状態
// ============================================================
let ws = null;
let adminWallet = null;
let isAuthenticated = false;
let networkStatus = {};
let nodes = [];
let trustedKeys = [];
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
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function $(id) {
    return document.getElementById(id);
}
function $val(id) {
    return document.getElementById(id).value.trim();
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
// ============================================================
// WebSocket
// ============================================================
function connect() {
    addLog('systemLog', 'シードノードに接続中...', 'info');
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        $('statusDot').classList.add('connected');
        $('statusText').textContent = '接続中';
        addLog('systemLog', '接続成功', 'success');
    };
    ws.onmessage = (event) => {
        const parts = event.data.split(DELIMITER);
        for (const part of parts) {
            if (!part.trim())
                continue;
            try {
                handlePacket(JSON.parse(part));
            }
            catch (e) {
                console.error('Packet parse error:', e);
            }
        }
    };
    ws.onclose = () => {
        $('statusDot').classList.remove('connected');
        $('statusText').textContent = '切断';
        addLog('systemLog', '切断、3秒後に再接続...', 'error');
        setTimeout(connect, 3000);
    };
    ws.onerror = () => {
        addLog('systemLog', '接続エラー', 'error');
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
        case 'admin_auth_result':
            if (packet.data.success) {
                isAuthenticated = true;
                adminWallet.role = packet.data.role;
                $('authStatus').textContent = `認証済み (${packet.data.role})`;
                $('mainTabs').style.display = 'flex';
                addLog('authLog', `認証成功: ${packet.data.role} ロール`, 'success');
                // 初期データ取得
                refreshDashboard();
            }
            else {
                isAuthenticated = false;
                addLog('authLog', `認証失敗: ${packet.data.message}`, 'error');
            }
            break;
        case 'admin_status':
            networkStatus = packet.data;
            updateDashboard();
            break;
        case 'admin_nodes':
            nodes = packet.data.nodes || [];
            updateNodesTable();
            break;
        case 'admin_trusted_keys':
            trustedKeys = packet.data.keys || [];
            updateTrustedKeysTable();
            break;
        case 'admin_account':
            if (packet.data.found) {
                displayAccountInfo(packet.data.account);
            }
            else {
                addLog('systemLog', 'アカウントが見つかりませんでした', 'warning');
            }
            break;
        case 'admin_blocks':
            updateBlocksTable(packet.data.blocks || []);
            break;
        case 'admin_mempool':
            updateMempool(packet.data);
            break;
        case 'admin_transactions':
            updateTransactions(packet.data.transactions || []);
            break;
        case 'add_member_result':
            if (packet.data.success) {
                addLog('keyLog', '鍵を追加しました', 'success');
                window.refreshTrustedKeys();
            }
            else {
                addLog('keyLog', '鍵の追加に失敗しました', 'error');
            }
            break;
        case 'admin_remove_key_result':
            if (packet.data.success) {
                addLog('keyLog', '鍵を削除しました', 'success');
                window.refreshTrustedKeys();
            }
            else {
                addLog('keyLog', '鍵の削除に失敗しました', 'error');
            }
            break;
        case 'admin_mint_result':
            if (packet.data.success) {
                addLog('systemLog', `コイン発行成功: ${packet.data.address} に ${packet.data.amount} BTR (新残高: ${packet.data.newBalance})`, 'success');
            }
            else {
                addLog('systemLog', `コイン発行失敗: ${packet.data.message || '不明なエラー'}`, 'error');
            }
            break;
        case 'admin_distribute_result':
            if (packet.data.success) {
                addLog('systemLog', `一括配給成功: ${packet.data.count} 件のアドレスに配布しました`, 'success');
            }
            else {
                addLog('systemLog', `一括配給失敗: ${packet.data.message || '不明なエラー'}`, 'error');
            }
            break;
        case 'admin_clear_mempool_result':
            if (packet.data.success) {
                addLog('systemLog', `Mempool全消去成功: ${packet.data.count} 件のトランザクションを削除しました`, 'success');
                window.refreshMempool();
            }
            else {
                addLog('systemLog', `Mempool全消去失敗: ${packet.data.message || '不明なエラー'}`, 'error');
            }
            break;
        case 'admin_remove_tx_result':
            if (packet.data.success) {
                addLog('systemLog', `トランザクション削除成功`, 'success');
                window.refreshMempool();
            }
            else {
                addLog('systemLog', `トランザクション削除失敗`, 'error');
            }
            break;
        case 'error':
            addLog('systemLog', `エラー: ${packet.data.message}`, 'error');
            break;
        default:
            // 未知のパケットは無視
            break;
    }
}
// ============================================================
// 認証
// ============================================================
window.authenticate = async function () {
    const privateKeyHex = $val('privateKey');
    if (privateKeyHex.length !== 64) {
        addLog('authLog', '秘密鍵は64文字のhexである必要があります', 'error');
        return;
    }
    try {
        const privateKeyBytes = hexToBytes(privateKeyHex);
        const publicKeyBytes = await Ed25519.getPublicKey(privateKeyBytes);
        const publicKeyHex = bytesToHex(publicKeyBytes);
        adminWallet = {
            privateKey: privateKeyHex,
            publicKey: publicKeyHex,
            role: null
        };
        $('publicKey').value = publicKeyHex;
        // チャレンジ署名を生成
        const challenge = Date.now().toString();
        const messageBytes = new TextEncoder().encode(challenge);
        const signatureBytes = await Ed25519.sign(messageBytes, privateKeyBytes);
        const signature = bytesToHex(signatureBytes);
        // 認証パケット送信
        send({
            type: 'admin_auth',
            data: {
                publicKey: publicKeyHex,
                challenge,
                signature
            }
        });
        addLog('authLog', '認証リクエストを送信しました...', 'info');
    }
    catch (e) {
        addLog('authLog', `認証エラー: ${e}`, 'error');
    }
};
window.generateAdminKey = async function () {
    const privateKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const privateKey = bytesToHex(privateKeyBytes);
    const publicKeyBytes = await Ed25519.getPublicKey(privateKeyBytes);
    const publicKey = bytesToHex(publicKeyBytes);
    $('privateKey').value = privateKey;
    $('publicKey').value = publicKey;
    addLog('authLog', '新しい管理者鍵を生成しました', 'success');
    addLog('authLog', `公開鍵: ${publicKey}`, 'info');
    addLog('authLog', 'この公開鍵をroot権限で信頼済み鍵に追加する必要があります', 'warning');
};
// ============================================================
// タブ切り替え
// ============================================================
window.switchTab = function (tabName) {
    // すべてのタブを非表示
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));
    // すべてのタブボタンを非アクティブ
    const buttons = document.querySelectorAll('.tab-button');
    buttons.forEach(btn => btn.classList.remove('active'));
    // 選択されたタブを表示
    const selectedTab = document.getElementById(`tab-${tabName}`);
    if (selectedTab)
        selectedTab.classList.add('active');
    // 対応するボタンをアクティブに
    event?.target && event.target.classList.add('active');
    // タブごとのデータ更新
    switch (tabName) {
        case 'dashboard':
            refreshDashboard();
            break;
        case 'nodes':
            window.refreshNodes();
            break;
        case 'keys':
            window.refreshTrustedKeys();
            break;
        case 'transactions':
            window.refreshTransactions();
            break;
        case 'blocks':
            window.refreshBlocks();
            break;
    }
};
// ============================================================
// ダッシュボード
// ============================================================
function refreshDashboard() {
    if (!isAuthenticated)
        return;
    send({ type: 'admin_status' });
    send({ type: 'admin_mempool' });
}
function updateDashboard() {
    if (networkStatus.nodeCount !== undefined) {
        $('nodeCount').textContent = networkStatus.nodeCount.toString();
    }
    if (networkStatus.clientCount !== undefined) {
        $('clientCount').textContent = networkStatus.clientCount.toString();
    }
    if (networkStatus.chainHeight !== undefined) {
        $('chainHeight').textContent = networkStatus.chainHeight.toString();
    }
    if (networkStatus.difficulty !== undefined) {
        $('difficulty').textContent = networkStatus.difficulty.toString();
    }
    if (networkStatus.latestBlock) {
        const block = networkStatus.latestBlock;
        $('latestBlockHeight').textContent = block.height?.toString() || '-';
        $('latestBlockMiner').textContent = block.miner || '-';
        $('latestBlockTxCount').textContent = block.transactions?.length?.toString() || '0';
        if (block.timestamp) {
            $('latestBlockTime').textContent = new Date(block.timestamp).toLocaleString();
        }
    }
}
window.refreshMempool = function () {
    if (!isAuthenticated)
        return;
    send({ type: 'admin_mempool' });
};
function updateMempool(data) {
    $('mempoolCount').textContent = data.count?.toString() || '0';
    const tbody = $('mempoolTableBody');
    const transactions = data.transactions || [];
    if (transactions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #888;">保留中のトランザクションなし</td></tr>';
        return;
    }
    tbody.innerHTML = transactions.map((tx) => `
    <tr>
      <td>${tx.type}</td>
      <td>${tx.from?.slice(0, 16) || 'N/A'}...</td>
      <td>${tx.to?.slice(0, 16) || 'N/A'}...</td>
      <td>${tx.amount || 'N/A'} BTR</td>
      <td>
        ${adminWallet?.role === 'root' ? `
          <button class="danger" onclick="removeTx('${tx.signature}')" style="width: auto; padding: 5px 10px;">削除</button>
        ` : ''}
      </td>
    </tr>
  `).join('');
}
// ============================================================
// ノード管理
// ============================================================
window.refreshNodes = function () {
    if (!isAuthenticated)
        return;
    send({ type: 'admin_nodes' });
};
function updateNodesTable() {
    const tbody = $('nodesTableBody');
    if (nodes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #888;">ノードなし</td></tr>';
        return;
    }
    tbody.innerHTML = nodes.map(node => `
    <tr>
      <td class="address small-text">${node.id}</td>
      <td>${new Date(node.connectedAt).toLocaleString()}</td>
      <td>${node.chainHeight}</td>
      <td>${new Date(node.lastPing).toLocaleTimeString()}</td>
    </tr>
  `).join('');
}
// ============================================================
// 信頼済み鍵管理
// ============================================================
window.refreshTrustedKeys = function () {
    if (!isAuthenticated)
        return;
    send({ type: 'admin_get_keys' });
};
function updateTrustedKeysTable() {
    const tbody = $('trustedKeysTableBody');
    if (trustedKeys.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #888;">鍵なし</td></tr>';
        return;
    }
    tbody.innerHTML = trustedKeys.map(key => `
    <tr>
      <td class="address small-text">${key.publicKey.slice(0, 20)}...</td>
      <td>${key.role}</td>
      <td class="address small-text">${key.addedBy.slice(0, 20)}...</td>
      <td><button class="danger" onclick="removeTrustedKey('${key.publicKey}')" ${adminWallet?.role !== 'root' ? 'disabled' : ''}>削除</button></td>
    </tr>
  `).join('');
}
window.addTrustedKey = async function () {
    if (!adminWallet || !isAuthenticated) {
        addLog('keyLog', '認証が必要です', 'error');
        return;
    }
    const newPublicKey = $val('newPublicKey');
    const role = $val('newKeyRole');
    if (newPublicKey.length !== 64) {
        addLog('keyLog', '公開鍵は64文字のhexである必要があります', 'error');
        return;
    }
    try {
        // 署名: sign(newPublicKey + role, adminの秘密鍵)
        const message = newPublicKey + role;
        const messageBytes = new TextEncoder().encode(message);
        const privateKeyBytes = hexToBytes(adminWallet.privateKey);
        const signatureBytes = await Ed25519.sign(messageBytes, privateKeyBytes);
        const signature = bytesToHex(signatureBytes);
        send({
            type: 'add_member',
            data: {
                publicKey: newPublicKey,
                role,
                addedBy: adminWallet.publicKey,
                signature
            }
        });
        addLog('keyLog', '鍵追加リクエストを送信しました...', 'info');
    }
    catch (e) {
        addLog('keyLog', `エラー: ${e}`, 'error');
    }
};
window.removeTrustedKey = function (publicKey) {
    if (!adminWallet || adminWallet.role !== 'root') {
        addLog('keyLog', 'root権限が必要です', 'error');
        return;
    }
    if (!confirm(`鍵を削除しますか？\n${publicKey}`)) {
        return;
    }
    send({
        type: 'admin_remove_key',
        data: {
            publicKey,
            removedBy: adminWallet.publicKey
        }
    });
    addLog('keyLog', '鍵削除リクエストを送信しました...', 'info');
};
// ============================================================
// トランザクション監視
// ============================================================
window.refreshTransactions = function () {
    if (!isAuthenticated)
        return;
    send({ type: 'admin_get_transactions', data: { limit: 50 } });
};
function updateTransactions(transactions) {
    const box = $('transactionsList');
    if (transactions.length === 0) {
        box.innerHTML = '<div style="color: #888; text-align: center;">トランザクションなし</div>';
        return;
    }
    box.innerHTML = transactions.map(tx => `
    <div>
      <strong>${tx.type}</strong> | 
      From: ${tx.from?.slice(0, 10)}... | 
      ${tx.to ? `To: ${tx.to.slice(0, 10)}...` : ''} | 
      ${tx.amount ? `Amount: ${tx.amount}` : ''} | 
      Fee: ${tx.fee} | 
      Time: ${new Date(tx.timestamp).toLocaleString()}
    </div>
  `).join('');
}
// ============================================================
// アカウント検索
// ============================================================
window.searchAccount = function () {
    if (!isAuthenticated)
        return;
    const address = $val('searchAddress');
    // BTRアドレスは 0x + 40文字のhex形式
    if (!address.startsWith('0x') || address.length !== 42) {
        addLog('systemLog', 'アドレスの形式が不正です (0x + 40文字)', 'error');
        return;
    }
    send({ type: 'admin_get_account', data: { address } });
};
function displayAccountInfo(account) {
    $('accountResult').style.display = 'block';
    $('accountAddress').textContent = account.address;
    $('accountBalance').textContent = account.balance?.toLocaleString() || '0';
    $('accountNonce').textContent = account.nonce?.toString() || '0';
    const tokensDiv = $('accountTokens');
    if (account.tokens && Object.keys(account.tokens).length > 0) {
        tokensDiv.innerHTML = Object.entries(account.tokens)
            .map(([addr, bal]) => `${addr.slice(0, 10)}...: ${bal}`)
            .join('<br>');
    }
    else {
        tokensDiv.innerHTML = 'トークン残高なし';
    }
}
// ============================================================
// ブロック履歴
// ============================================================
window.refreshBlocks = function () {
    if (!isAuthenticated)
        return;
    const count = parseInt($val('blockCount')) || 10;
    send({ type: 'admin_get_blocks', data: { limit: count } });
};
function updateBlocksTable(blocks) {
    const tbody = $('blocksTableBody');
    if (blocks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #888;">ブロックなし</td></tr>';
        return;
    }
    tbody.innerHTML = blocks.map(block => `
    <tr>
      <td>${block.height}</td>
      <td class="address small-text">${block.hash?.slice(0, 20)}...</td>
      <td class="address small-text">${block.miner?.slice(0, 10)}...</td>
      <td>${block.transactions?.length || 0}</td>
      <td>${new Date(block.timestamp).toLocaleString()}</td>
    </tr>
  `).join('');
}
// ============================================================
// コイン管理機能 (root only)
// ============================================================
window.mintCoins = function () {
    if (!isAuthenticated || adminWallet?.role !== 'root') {
        addLog('systemLog', 'コイン発行にはroot権限が必要です', 'error');
        return;
    }
    const address = $val('mintAddress');
    const amountStr = $val('mintAmount');
    if (!address || !amountStr) {
        addLog('systemLog', 'アドレスと金額を入力してください', 'error');
        return;
    }
    // Validate address format (basic hex check)
    if (!address.startsWith('0x') || address.length !== 42) {
        addLog('systemLog', 'アドレスの形式が不正です (0x + 40文字)', 'error');
        return;
    }
    const amount = parseFloat(amountStr);
    if (isNaN(amount) || amount <= 0) {
        addLog('systemLog', '有効な金額を入力してください', 'error');
        return;
    }
    // Add maximum limit check
    if (amount > 1_000_000_000) {
        addLog('systemLog', '金額が大きすぎます（最大: 1,000,000,000 BTR）', 'error');
        return;
    }
    send({ type: 'admin_mint', data: { address, amount } });
    addLog('systemLog', `コイン発行リクエスト送信: ${address} に ${amount} BTR`, 'info');
};
window.distributeCoins = function () {
    if (!isAuthenticated || adminWallet?.role !== 'root') {
        addLog('systemLog', '一括配給にはroot権限が必要です', 'error');
        return;
    }
    const distributionText = $val('distributionList');
    if (!distributionText.trim()) {
        addLog('systemLog', '配布リストを入力してください', 'error');
        return;
    }
    const lines = distributionText.trim().split('\n');
    const distributions = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line)
            continue;
        const parts = line.split(',');
        if (parts.length !== 2) {
            addLog('systemLog', `行 ${i + 1}: フォーマットエラー（アドレス,金額 の形式で入力してください）`, 'error');
            return;
        }
        const address = parts[0].trim();
        const amount = parseFloat(parts[1].trim());
        // Validate address format
        if (!/^0x[0-9a-fA-F]{16}$/.test(address) && !/^[0-9a-fA-F]{16}$/.test(address)) {
            addLog('systemLog', `行 ${i + 1}: アドレスの形式が正しくありません`, 'error');
            return;
        }
        if (!address || isNaN(amount) || amount <= 0) {
            addLog('systemLog', `行 ${i + 1}: 無効なアドレスまたは金額`, 'error');
            return;
        }
        if (amount > 1_000_000_000) {
            addLog('systemLog', `行 ${i + 1}: 金額が大きすぎます（最大: 1,000,000,000 BTR）`, 'error');
            return;
        }
        distributions.push({ address, amount });
    }
    if (distributions.length === 0) {
        addLog('systemLog', '有効な配布先がありません', 'error');
        return;
    }
    send({ type: 'admin_distribute', data: { distributions } });
    addLog('systemLog', `一括配給リクエスト送信: ${distributions.length} 件`, 'info');
};
window.clearMempool = function () {
    if (!isAuthenticated || adminWallet?.role !== 'root') {
        addLog('systemLog', 'Mempool全消去にはroot権限が必要です', 'error');
        return;
    }
    if (!confirm('本当にMempool内の全てのトランザクションを削除しますか？')) {
        return;
    }
    send({ type: 'admin_clear_mempool', data: {} });
    addLog('systemLog', 'Mempool全消去リクエスト送信', 'info');
};
window.removeTx = function (signature) {
    if (!isAuthenticated || adminWallet?.role !== 'root') {
        addLog('systemLog', 'トランザクション削除にはroot権限が必要です', 'error');
        return;
    }
    if (!confirm('このトランザクションを削除しますか？')) {
        return;
    }
    send({ type: 'admin_remove_tx', data: { signature } });
    addLog('systemLog', `トランザクション削除リクエスト送信: ${signature.slice(0, 16)}...`, 'info');
};
// ============================================================
// 初期化
// ============================================================
function init() {
    console.log('BTR Admin Panel Initializing...');
    connect();
    // 定期的にダッシュボード更新（認証済みの場合のみ）
    setInterval(() => {
        if (isAuthenticated) {
            refreshDashboard();
        }
    }, 30000);
}
// DOM読み込み完了後に初期化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
}
else {
    init();
}
//# sourceMappingURL=admin.js.map