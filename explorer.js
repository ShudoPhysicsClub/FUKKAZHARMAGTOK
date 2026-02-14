// BTR Explorer JavaScript

const WS_URL = 'wss://shudo-physics.f5.si:443';
let ws = null;
let clientId = Math.random().toString(36).slice(2);

// 状態
let currentView = 'list'; // 'list' or 'detail'
let cachedBlocks = [];
let cachedTransactions = [];
let cachedAccounts = new Map();

// ============================================================
// WebSocket接続
// ============================================================

function connect() {
  console.log('Connecting to', WS_URL);
  ws = new WebSocket(WS_URL);
  
  ws.onopen = () => {
    console.log('Connected to BTR network');
    document.getElementById('statHeight').textContent = '接続中...';
    loadInitialData();
  };
  
  ws.onmessage = (event) => {
    try {
      const packet = JSON.parse(event.data);
      console.log('Received:', packet.type);
      handlePacket(packet);
    } catch (e) {
      console.error('Parse error:', e);
    }
  };
  
  ws.onclose = () => {
    console.log('Disconnected, reconnecting in 3s...');
    document.getElementById('statHeight').textContent = '切断';
    setTimeout(connect, 3000);
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
    document.getElementById('statHeight').textContent = 'エラー';
  };
}

function send(packet) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(packet));
  }
}

// ============================================================
// パケットハンドリング
// ============================================================

function handlePacket(packet) {
  switch (packet.type) {
    case 'height':
      updateStats(packet.data);
      break;
    case 'chain_chunk':
      handleBlocks(packet.data.blocks);
      break;
    case 'transactions':
      handleTransactions(packet.data.transactions);
      break;
    case 'balance':
      handleAccountData(packet.data);
      break;
    case 'mempool':
      handleMempool(packet.data);
      break;
    case 'block':
      showBlockDetail(packet.data.block);
      break;
  }
}

// ============================================================
// データ取得
// ============================================================

function loadInitialData() {
  // 統計情報取得
  send({ type: 'get_height', data: { clientId } });
  
  // 最新50ブロック取得
  send({ type: 'get_chain', data: { clientId, from: -50, to: -1 } });
  
  // 最新50トランザクション取得
  send({ type: 'get_recent_transactions', data: { clientId, limit: 50 } });
  
  // メモリプール取得
  send({ type: 'get_mempool', data: { clientId } });
}

function updateStats(data) {
  document.getElementById('statHeight').textContent = data.height || '-';
  document.getElementById('statPending').textContent = data.pendingCount || '-';
  
  // アカウント数とSupplyは別途取得が必要
  // 仮の値
  document.getElementById('statAccounts').textContent = cachedAccounts.size || '-';
  document.getElementById('statSupply').textContent = '-';
}

function handleBlocks(blocks) {
  cachedBlocks = blocks.sort((a, b) => b.height - a.height);
  renderBlocks();
}

function handleTransactions(txs) {
  cachedTransactions = txs;
  renderTransactions();
}

function handleAccountData(data) {
  cachedAccounts.set(data.address, data);
  // アカウントタブがアクティブな場合のみレンダリング
  if (document.getElementById('panel-accounts').classList.contains('active')) {
    renderAccounts();
  }
}

function handleMempool(data) {
  renderMempool(data.transactions);
}

// ============================================================
// レンダリング
// ============================================================

function renderBlocks() {
  const list = document.getElementById('blockList');
  
  if (cachedBlocks.length === 0) {
    list.innerHTML = '<div class="loading">ブロックがありません</div>';
    return;
  }
  
  list.innerHTML = cachedBlocks.map(block => `
    <div class="list-item" onclick="showBlock(${block.height})">
      <div class="item-header">
        <div class="item-title">Block #${block.height}</div>
        <div class="item-time">${formatTime(block.timestamp)}</div>
      </div>
      <div class="item-details">
        <div>Miner: <span class="address" onclick="event.stopPropagation(); searchAddress('${block.miner}')">${block.miner.slice(0, 20)}...</span></div>
        <div>Transactions: ${block.transactions.length} | Difficulty: ${block.difficulty}</div>
        <div class="hash">Hash: ${block.hash}</div>
      </div>
    </div>
  `).join('');
}

function renderTransactions() {
  const list = document.getElementById('txList');
  
  if (cachedTransactions.length === 0) {
    list.innerHTML = '<div class="loading">トランザクションがありません</div>';
    return;
  }
  
  list.innerHTML = cachedTransactions.map(tx => `
    <div class="list-item">
      <div class="item-header">
        <div class="item-title">${getTxTypeLabel(tx.type)}</div>
        <div class="item-time">${formatTime(tx.timestamp)}</div>
      </div>
      <div class="item-details">
        <div>From: <span class="address" onclick="searchAddress('${tx.from}')">${tx.from.slice(0, 20)}...</span></div>
        ${tx.to ? `<div>To: <span class="address" onclick="searchAddress('${tx.to}')">${tx.to.slice(0, 20)}...</span></div>` : ''}
        ${tx.amount ? `<div>Amount: ${tx.amount} BTR</div>` : ''}
        <div class="hash">Signature: ${tx.signature.slice(0, 40)}...</div>
      </div>
    </div>
  `).join('');
}

function renderAccounts() {
  const list = document.getElementById('accountList');
  const accounts = Array.from(cachedAccounts.values());
  
  if (accounts.length === 0) {
    list.innerHTML = '<div class="loading">上の検索ボックスにアドレスを入力して検索してください<br><br>例: 0x5a5fe88fbc77f9342134bde1f715d4b970e48a57</div>';
    return;
  }
  
  list.innerHTML = accounts.map(account => `
    <div class="list-item" onclick="searchAddress('${account.address}')">
      <div class="item-header">
        <div class="item-title">${account.address.slice(0, 30)}...</div>
        <div style="color: var(--accent); font-family: var(--mono);">${account.balance} BTR</div>
      </div>
      <div class="item-details">
        <div>Nonce: ${account.nonce}</div>
        ${Object.keys(account.tokens || {}).length > 0 ? `<div>Tokens: ${Object.keys(account.tokens).length}</div>` : ''}
      </div>
    </div>
  `).join('');
}

function renderMempool(txs) {
  const list = document.getElementById('mempoolList');
  
  if (!txs || txs.length === 0) {
    list.innerHTML = '<div class="loading">メモリプールは空です</div>';
    return;
  }
  
  list.innerHTML = txs.map(tx => `
    <div class="list-item">
      <div class="item-header">
        <div class="item-title">${getTxTypeLabel(tx.type)}</div>
        <div><span class="status status-success">Pending</span></div>
      </div>
      <div class="item-details">
        <div>From: <span class="address" onclick="searchAddress('${tx.from}')">${tx.from.slice(0, 20)}...</span></div>
        ${tx.to ? `<div>To: <span class="address" onclick="searchAddress('${tx.to}')">${tx.to.slice(0, 20)}...</span></div>` : ''}
        ${tx.amount ? `<div>Amount: ${tx.amount}</div>` : ''}
      </div>
    </div>
  `).join('');
}

// ============================================================
// 詳細表示
// ============================================================

function showBlock(height) {
  send({ type: 'get_block', data: { clientId, height } });
}

function showBlockDetail(block) {
  if (!block) return;
  
  const content = document.getElementById('detailContent');
  content.innerHTML = `
    <h2 style="color: var(--accent); margin-bottom: 20px;">Block #${block.height}</h2>
    
    <div class="detail-section">
      <div class="detail-label">Hash</div>
      <div class="detail-value">${block.hash}</div>
    </div>
    
    <div class="detail-section">
      <div class="detail-label">Previous Hash</div>
      <div class="detail-value">${block.previousHash}</div>
    </div>
    
    <div class="detail-section">
      <div class="detail-label">Timestamp</div>
      <div class="detail-value">${new Date(block.timestamp).toLocaleString('ja-JP')}</div>
    </div>
    
    <div class="detail-section">
      <div class="detail-label">Miner</div>
      <div class="detail-value"><span class="address" onclick="searchAddress('${block.miner}')">${block.miner}</span></div>
    </div>
    
    <div class="detail-section">
      <div class="detail-label">Difficulty</div>
      <div class="detail-value">${block.difficulty}</div>
    </div>
    
    <div class="detail-section">
      <div class="detail-label">Nonce</div>
      <div class="detail-value">${block.nonce}</div>
    </div>
    
    <div class="detail-section">
      <div class="detail-label">Reward</div>
      <div class="detail-value">${block.reward} BTR</div>
    </div>
    
    <div class="detail-section">
      <div class="detail-label">Transactions (${block.transactions.length})</div>
      ${block.transactions.length > 0 ? `
        <table style="margin-top: 10px;">
          <thead>
            <tr>
              <th>Type</th>
              <th>From</th>
              <th>To</th>
              <th>Amount</th>
            </tr>
          </thead>
          <tbody>
            ${block.transactions.map(tx => `
              <tr>
                <td>${getTxTypeLabel(tx.type)}</td>
                <td><span class="address" onclick="searchAddress('${tx.from}')">${tx.from.slice(0, 10)}...</span></td>
                <td>${tx.to ? `<span class="address" onclick="searchAddress('${tx.to}')">${tx.to.slice(0, 10)}...</span>` : '-'}</td>
                <td>${tx.amount || '-'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : '<div style="color: var(--text2); margin-top: 10px;">トランザクションなし</div>'}
    </div>
  `;
  
  document.getElementById('detailArea').style.display = 'block';
  document.querySelectorAll('.panel').forEach(p => p.style.display = 'none');
}

function closeDetail() {
  document.getElementById('detailArea').style.display = 'none';
  document.querySelectorAll('.panel').forEach(p => {
    if (p.classList.contains('active')) {
      p.style.display = 'block';
    }
  });
}

// ============================================================
// 検索
// ============================================================

function searchAddress(address) {
  send({ type: 'get_balance', data: { clientId, address } });
  
  // アカウントタブに切り替え
  switchTab('accounts');
}

document.getElementById('searchInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    const query = e.target.value.trim();
    if (!query) return;
    
    // アドレスっぽい（0xで始まる）
    if (query.startsWith('0x')) {
      searchAddress(query);
    }
    // 数字のみ（ブロック高さ）
    else if (/^\d+$/.test(query)) {
      showBlock(parseInt(query));
    }
  }
});

// ============================================================
// タブ切り替え
// ============================================================

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const panel = tab.dataset.panel;
    switchTab(panel);
  });
});

function switchTab(panelName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  
  const targetTab = document.querySelector(`.tab[data-panel="${panelName}"]`);
  const targetPanel = document.getElementById(`panel-${panelName}`);
  
  if (targetTab) targetTab.classList.add('active');
  if (targetPanel) targetPanel.classList.add('active');
  
  closeDetail();
}

// ============================================================
// ユーティリティ
// ============================================================

function formatTime(timestamp) {
  const date = new Date(timestamp);
  const now = Date.now();
  const diff = now - timestamp;
  
  if (diff < 60000) return '数秒前';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}分前`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}時間前`;
  return date.toLocaleDateString('ja-JP');
}

function getTxTypeLabel(type) {
  const labels = {
    'transfer': '送金',
    'create_token': 'トークン作成',
    'token_transfer': 'トークン送金',
    'swap': 'スワップ',
    'rename_token': 'トークン名変更'
  };
  return labels[type] || type;
}

// ============================================================
// 起動
// ============================================================

connect();