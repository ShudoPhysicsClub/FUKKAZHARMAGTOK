// ============================================================
// BTR (Buturi Coin) - シードノード メインサーバー
// ============================================================
import net from 'net';
import { WebSocketServer } from 'ws';
import { createServer as createHTTPSServer } from 'https';
import { createServer as createHTTPServer } from 'http';
import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { PacketBuffer, sendTCP, sendWS } from './protocol.js';
import { TrustManager } from './trust.js';
import { RandomManager } from './random.js';
import { Ed25519 } from './crypto.js';
// ============================================================
// 設定
// ============================================================
const CONFIG = {
    ROOT_PUBLIC_KEY: '04920517f44339fed12ebbc8f2c0ae93a0c2bfa4a9ef4bfee1c6f12b452eab70',
    TCP_PORT: 5000,
    WSS_PORT: 443,
    WSS_DEV_PORT: 8443,
    SEED_PORT: 40000,
    HEARTBEAT_INTERVAL: 5000,
    HEARTBEAT_TIMEOUT: 15000,
    RANDOM_INTERVAL: 60 * 60 * 1000,
    RANDOM_TIMEOUT: 10000,
    SSL_CERT: '/etc/letsencrypt/live/shudo-physics.f5.si/fullchain.pem',
    SSL_KEY: '/etc/letsencrypt/live/shudo-physics.f5.si/privkey.pem',
    SEEDS_PATH: 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/seeds.json',
};
const fullNodes = new Map();
const clients = new Map();
const seedPeers = new Map();
let trustManager;
let randomManager;
let latestNodeCode = null;
let myPriority = 1;
let isPrimary = true;
let nodeIdCounter = 0;
let clientIdCounter = 0;
function generateId(prefix) {
    const counter = prefix === 'node' ? ++nodeIdCounter : ++clientIdCounter;
    return `${prefix}_${Date.now()}_${counter}`;
}
function log(category, message) {
    const time = new Date().toISOString().slice(11, 19);
    console.log(`[${time}][${category}] ${message}`);
}
// ============================================================
// ヘルパー関数
// ============================================================
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
// ============================================================
// seeds.json & シードノード間接続
// ============================================================
function loadSeeds() {
    try {
        if (fs.existsSync(CONFIG.SEEDS_PATH)) {
            const data = JSON.parse(fs.readFileSync(CONFIG.SEEDS_PATH, 'utf-8'));
            log('Seeds', `${data.seeds.length}件のシードノード読み込み`);
            return data.seeds;
        }
    }
    catch (e) {
        log('Seeds', `seeds.json 読み込み失敗: ${e}`);
    }
    return [];
}
function getMyHost() {
    return process.env.SEED_HOST || 'mail.shudo-physics.com';
}
function connectToSeeds() {
    const seeds = loadSeeds();
    const myHost = getMyHost();
    for (const seed of seeds) {
        if (seed.host === myHost) {
            myPriority = seed.priority;
            log('Seeds', `自分を検出: priority ${myPriority}`);
            continue;
        }
        connectToSeed(seed);
    }
    determinePrimary();
}
function connectToSeed(seed) {
    if (seedPeers.has(seed.host))
        return;
    log('Seeds', `シードノードに接続中: ${seed.host}:${CONFIG.SEED_PORT}`);
    const socket = net.connect(CONFIG.SEED_PORT, seed.host, () => {
        log('Seeds', `シードノード接続成功: ${seed.host}`);
        const buffer = new PacketBuffer();
        const conn = {
            socket, buffer,
            host: seed.host,
            priority: seed.priority,
            publicKey: seed.publicKey,
            lastPing: Date.now(),
        };
        seedPeers.set(seed.host, conn);
        sendTCP(socket, { type: 'seed_hello', data: { host: getMyHost(), priority: myPriority } });
        sendTCP(socket, { type: 'sync_trusted_keys', data: trustManager.getTrustedKeysFile() });
        socket.on('data', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets)
                handleSeedPacket(seed.host, packet);
        });
        socket.on('close', () => {
            seedPeers.delete(seed.host);
            log('Seeds', `シードノード切断: ${seed.host}`);
            setTimeout(() => connectToSeed(seed), 3000);
            determinePrimary();
        });
        socket.on('error', (err) => {
            log('Seeds', `シードノードエラー (${seed.host}): ${err.message}`);
        });
    });
    socket.on('error', (err) => {
        log('Seeds', `シードノード接続失敗 (${seed.host}): ${err.message}`);
        setTimeout(() => connectToSeed(seed), 5000);
    });
}
function determinePrimary() {
    let lowestPriority = myPriority;
    for (const [, conn] of seedPeers) {
        if (conn.priority < lowestPriority)
            lowestPriority = conn.priority;
    }
    const wasPrimary = isPrimary;
    isPrimary = (myPriority === lowestPriority);
    if (isPrimary !== wasPrimary) {
        log('Seeds', isPrimary ? '★ プライマリに昇格' : '→ セカンダリに降格');
    }
}
function findPrimaryHost() {
    let primaryHost = getMyHost();
    let lowestPriority = myPriority;
    for (const [host, conn] of seedPeers) {
        if (conn.priority < lowestPriority) {
            lowestPriority = conn.priority;
            primaryHost = host;
        }
    }
    return primaryHost;
}
function broadcastToSeeds(packet) {
    for (const [, conn] of seedPeers)
        sendTCP(conn.socket, packet);
}
// ============================================================
// シードノード間TCPサーバー（ポート40000）
// ============================================================
function startSeedServer() {
    const server = net.createServer((socket) => {
        const buffer = new PacketBuffer();
        let peerHost = socket.remoteAddress || 'unknown';
        log('Seeds', `シードノードからの接続受付: ${peerHost}`);
        socket.on('data', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets) {
                if (packet.type === 'seed_hello' && packet.data?.host) {
                    peerHost = packet.data.host;
                    if (!seedPeers.has(peerHost)) {
                        seedPeers.set(peerHost, {
                            socket, buffer,
                            host: peerHost,
                            priority: packet.data.priority || 999,
                            publicKey: '',
                            lastPing: Date.now(),
                        });
                        log('Seeds', `シードノード登録: ${peerHost} (priority: ${packet.data.priority})`);
                        determinePrimary();
                    }
                }
                handleSeedPacket(peerHost, packet);
            }
        });
        socket.on('close', () => {
            seedPeers.delete(peerHost);
            log('Seeds', `シードノード切断（受付側）: ${peerHost}`);
            determinePrimary();
        });
        socket.on('error', (err) => {
            log('Seeds', `シードノードエラー（受付側）: ${err.message}`);
        });
    });
    server.listen(CONFIG.SEED_PORT, () => {
        log('Seeds', `シードノード間TCPサーバー起動: port ${CONFIG.SEED_PORT}`);
    });
}
// ============================================================
// シードノード間パケットハンドリング
// ============================================================
function handleSeedPacket(peerHost, packet) {
    const conn = seedPeers.get(peerHost);
    switch (packet.type) {
        case 'seed_hello': break;
        case 'ping':
            if (conn) {
                conn.lastPing = Date.now();
                sendTCP(conn.socket, { type: 'pong' });
            }
            break;
        case 'pong':
            if (conn)
                conn.lastPing = Date.now();
            break;
        case 'sync_trusted_keys':
            if (packet.data) {
                trustManager.syncTrustedKeys(packet.data);
                log('Seeds', `trusted_keys 同期受信: ${peerHost}`);
            }
            break;
        case 'who_is_primary':
            if (conn)
                sendTCP(conn.socket, { type: 'primary_is', data: { host: findPrimaryHost() } });
            break;
        case 'random_result':
            broadcastToNodes(packet);
            broadcastToClients(packet);
            break;
        case 'update':
            if (packet.data) {
                trustManager.verifyUpdate(packet.data).then(valid => {
                    if (valid) {
                        latestNodeCode = packet.data;
                        fs.writeFileSync('./latest_update.json', JSON.stringify(packet.data));
                        broadcastToNodes(packet);
                        log('Seeds', `アップデート同期: v${packet.data.version} from ${peerHost}`);
                    }
                });
            }
            break;
        case 'block_broadcast':
            broadcastToNodes(packet);
            broadcastToClients({ type: 'new_block', data: packet.data });
            break;
        default:
            log('Seeds', `不明なシード間パケット: ${packet.type} from ${peerHost}`);
    }
}
function startSeedHeartbeat() {
    setInterval(() => {
        const now = Date.now();
        for (const [host, conn] of seedPeers) {
            if (now - conn.lastPing > CONFIG.HEARTBEAT_TIMEOUT) {
                log('Seeds', `シードノードタイムアウト: ${host}`);
                conn.socket.destroy();
                seedPeers.delete(host);
                determinePrimary();
                continue;
            }
            sendTCP(conn.socket, { type: 'ping', timestamp: now });
        }
    }, CONFIG.HEARTBEAT_INTERVAL);
}
// ============================================================
// TCPサーバー（フルノード用 :5000）
// ============================================================
function startTCPServer() {
    const server = net.createServer((socket) => {
        const nodeId = generateId('node');
        const buffer = new PacketBuffer();
        const conn = {
            socket, buffer,
            info: { id: nodeId, host: socket.remoteAddress, connectedAt: Date.now(), lastPing: Date.now(), chainHeight: 0 }
        };
        fullNodes.set(nodeId, conn);
        log('TCP', `フルノード接続: ${nodeId} (${socket.remoteAddress})`);
        broadcastToNodes({ type: 'new_node', data: { id: nodeId, host: socket.remoteAddress } }, nodeId);
        socket.on('data', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets)
                handleNodePacket(nodeId, packet);
        });
        socket.on('close', () => {
            fullNodes.delete(nodeId);
            log('TCP', `フルノード切断: ${nodeId}`);
            broadcastToNodes({ type: 'node_left', data: { id: nodeId } });
        });
        socket.on('error', (err) => log('TCP', `エラー (${nodeId}): ${err.message}`));
    });
    server.listen(CONFIG.TCP_PORT, () => {
        log('TCP', `フルノード用TCPサーバー起動: port ${CONFIG.TCP_PORT}`);
    });
}
// ============================================================
// WSSサーバー（クライアント用 :443 / :8443）
// ============================================================
function startWSSServer() {
    let server;
    if (fs.existsSync(CONFIG.SSL_CERT) && fs.existsSync(CONFIG.SSL_KEY)) {
        server = createHTTPSServer({
            cert: fs.readFileSync(CONFIG.SSL_CERT),
            key: fs.readFileSync(CONFIG.SSL_KEY),
        });
        server.listen(CONFIG.WSS_PORT, () => {
            log('WSS', `クライアント用WSSサーバー起動: port ${CONFIG.WSS_PORT} (HTTPS)`);
        });
    }
    else {
        server = createHTTPServer();
        server.listen(CONFIG.WSS_DEV_PORT, () => {
            log('WSS', `クライアント用WSサーバー起動: port ${CONFIG.WSS_DEV_PORT} (HTTP, 開発モード)`);
        });
    }
    const wss = new WebSocketServer({ server });
    wss.on('connection', (ws) => {
        const clientId = generateId('client');
        const buffer = new PacketBuffer();
        const conn = { ws, buffer, id: clientId, connectedAt: Date.now() };
        clients.set(clientId, conn);
        log('WSS', `クライアント接続: ${clientId}`);
        ws.on('message', (data) => {
            const packets = buffer.feed(data.toString());
            for (const packet of packets)
                handleClientPacket(clientId, packet);
        });
        ws.on('close', () => { clients.delete(clientId); log('WSS', `クライアント切断: ${clientId}`); });
        ws.on('error', (err) => log('WSS', `エラー (${clientId}): ${err.message}`));
    });
}
// ============================================================
// パケットハンドリング（フルノード）
// ============================================================
function handleNodePacket(nodeId, packet) {
    const conn = fullNodes.get(nodeId);
    if (!conn)
        return;
    switch (packet.type) {
        case 'pong':
            conn.info.lastPing = Date.now();
            break;
        case 'register':
            conn.info.chainHeight = packet.data?.chainHeight || 0;
            sendTCP(conn.socket, {
                type: 'node_list',
                data: { nodes: Array.from(fullNodes.values()).map(n => ({ id: n.info.id, host: n.info.host, chainHeight: n.info.chainHeight })) }
            });
            log('TCP', `ノード登録: ${nodeId} (height: ${conn.info.chainHeight})`);
            break;
        case 'height':
            conn.info.chainHeight = packet.data?.height || 0;
            if (packet.data?.clientId) {
                const client = clients.get(packet.data.clientId);
                if (client)
                    sendWS(client.ws, packet);
            }
            break;
        case 'block_broadcast':
            broadcastToNodes(packet, nodeId);
            broadcastToSeeds(packet);
            break;
        case 'tx_broadcast':
            broadcastToNodes(packet, nodeId);
            break;
        case 'block_accepted': {
            broadcastToClients({ type: 'new_block', data: packet.data });
            if (packet.data?.minerId) {
                const client = clients.get(packet.data.minerId);
                if (client)
                    sendWS(client.ws, { type: 'block_accepted', data: packet.data });
            }
            break;
        }
        case 'block_rejected': {
            if (packet.data?.minerId) {
                const client = clients.get(packet.data.minerId);
                if (client)
                    sendWS(client.ws, { type: 'block_rejected', data: packet.data });
            }
            break;
        }
        case 'balance':
        case 'chain':
        case 'chain_chunk':
        case 'chain_sync_done':
        case 'token_info':
        case 'rate':
        case 'tx_result':
        case 'block_template':
        case 'admin_mempool':
        case 'admin_transactions':
        case 'admin_account':
        case 'admin_blocks':
        case 'admin_mint_result':
        case 'admin_distribute_result':
        case 'admin_clear_mempool_result':
        case 'admin_remove_tx_result':
            if (packet.data?.clientId) {
                const client = clients.get(packet.data.clientId);
                if (client)
                    sendWS(client.ws, packet);
            }
            break;
        case 'random_commit':
            handleRandomCommit(nodeId, packet);
            break;
        case 'random_reveal':
            handleRandomReveal(nodeId, packet);
            break;
        case 'get_latest_files':
            sendTCP(conn.socket, { type: 'latest_files', data: { nodeCode: latestNodeCode, trustedKeys: trustManager.getTrustedKeysFile() } });
            log('TCP', `最新ファイル配布: ${nodeId}`);
            break;
        case 'who_is_primary':
            sendTCP(conn.socket, { type: 'primary_is', data: { host: findPrimaryHost() } });
            break;
        default: log('TCP', `不明なパケット: ${packet.type} from ${nodeId}`);
    }
}
// ============================================================
// パケットハンドリング（クライアント）
// ============================================================
function handleClientPacket(clientId, packet) {
    const conn = clients.get(clientId);
    if (!conn)
        return;
    switch (packet.type) {
        case 'mine':
            broadcastToNodes({ type: 'block_broadcast', data: { ...packet.data, minerId: clientId } });
            break;
        case 'tx':
            relayToNode({ type: 'tx', data: { ...packet.data, clientId } });
            break;
        case 'get_balance':
        case 'get_chain':
        case 'get_height':
        case 'get_token':
        case 'get_rate':
        case 'get_block_template':
            relayToNode({ type: packet.type, data: { ...packet.data, clientId } });
            break;
        case 'update':
            handleUpdateFromClient(clientId, packet);
            break;
        case 'add_member':
            handleAddMember(clientId, packet);
            break;
        case 'admin_auth':
            handleAdminAuth(clientId, packet);
            break;
        case 'admin_status':
            handleAdminStatus(clientId);
            break;
        case 'admin_nodes':
            handleAdminNodes(clientId);
            break;
        case 'admin_get_keys':
            handleAdminGetKeys(clientId);
            break;
        case 'admin_get_account':
            handleAdminGetAccount(clientId, packet);
            break;
        case 'admin_get_blocks':
            handleAdminGetBlocks(clientId, packet);
            break;
        case 'admin_mempool':
            handleAdminMempool(clientId);
            break;
        case 'admin_get_transactions':
            handleAdminGetTransactions(clientId, packet);
            break;
        case 'admin_remove_key':
            handleAdminRemoveKey(clientId, packet);
            break;
        case 'admin_mint':
            handleAdminMint(clientId, packet);
            break;
        case 'admin_distribute':
            handleAdminDistribute(clientId, packet);
            break;
        case 'admin_clear_mempool':
            handleAdminClearMempool(clientId);
            break;
        case 'admin_remove_tx':
            handleAdminRemoveTx(clientId, packet);
            break;
        default: log('WSS', `不明なパケット: ${packet.type} from ${clientId}`);
    }
}
// ============================================================
// 中継
// ============================================================
function broadcastToNodes(packet, excludeId) {
    for (const [id, conn] of fullNodes) {
        if (id !== excludeId)
            sendTCP(conn.socket, packet);
    }
}
function broadcastToClients(packet) {
    for (const [, conn] of clients)
        sendWS(conn.ws, packet);
}
function relayToNode(packet) {
    const nodes = Array.from(fullNodes.values());
    if (nodes.length === 0) {
        if (packet.data?.clientId) {
            const client = clients.get(packet.data.clientId);
            if (client)
                sendWS(client.ws, { type: 'error', data: { message: 'フルノードが利用できません' } });
        }
        return;
    }
    const best = nodes.reduce((a, b) => a.info.chainHeight >= b.info.chainHeight ? a : b);
    sendTCP(best.socket, packet);
}
// ============================================================
// アップデート & メンバー管理
// ============================================================
async function handleUpdateFromClient(clientId, packet) {
    const update = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    if (!await trustManager.verifyUpdate(update)) {
        sendWS(client.ws, { type: 'update_result', data: { success: false, message: '検証失敗' } });
        return;
    }
    latestNodeCode = update;
    fs.writeFileSync('./latest_update.json', JSON.stringify(update));
    log('Update', `アップデート受信: v${update.version} by ${update.signer.slice(0, 16)}...`);
    broadcastToNodes({ type: 'update', data: update });
    broadcastToSeeds({ type: 'update', data: update });
    sendWS(client.ws, { type: 'update_result', data: { success: true, message: `v${update.version} を配布しました` } });
}
async function handleAddMember(clientId, packet) {
    const { publicKey, role, addedBy, signature } = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    const success = await trustManager.addMember(publicKey, role, addedBy, signature);
    sendWS(client.ws, { type: 'add_member_result', data: { success } });
    if (success) {
        const keysData = trustManager.getTrustedKeysFile();
        broadcastToNodes({ type: 'sync_trusted_keys', data: keysData });
        broadcastToSeeds({ type: 'sync_trusted_keys', data: keysData });
    }
}
// ============================================================
// 管理者パネル用ハンドラ
// ============================================================
async function handleAdminAuth(clientId, packet) {
    const { publicKey, challenge, signature } = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    try {
        if (!trustManager.isTrusted(publicKey)) {
            sendWS(client.ws, {
                type: 'admin_auth_result',
                data: { success: false, message: '信頼されていない公開鍵です' }
            });
            return;
        }
        const messageBytes = new TextEncoder().encode(challenge);
        const signatureBytes = hexToBytes(signature);
        const publicKeyBytes = hexToBytes(publicKey);
        const isValid = await Ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
        if (!isValid) {
            sendWS(client.ws, {
                type: 'admin_auth_result',
                data: { success: false, message: '署名検証失敗' }
            });
            return;
        }
        const role = trustManager.getRole(publicKey);
        client.authenticatedKey = publicKey;
        client.adminRole = role;
        sendWS(client.ws, {
            type: 'admin_auth_result',
            data: { success: true, role }
        });
        log('Admin', `管理者認証成功: ${publicKey.slice(0, 16)}... (${role})`);
    }
    catch (e) {
        log('Admin', `認証エラー: ${e instanceof Error ? e.message : String(e)}`);
        console.error('Admin auth error details:', e);
        sendWS(client.ws, {
            type: 'admin_auth_result',
            data: { success: false, message: '認証エラー' }
        });
    }
}
function isAdminAuthenticated(clientId) {
    const client = clients.get(clientId);
    if (!client)
        return false;
    return !!client.authenticatedKey;
}
function getAdminRole(clientId) {
    const client = clients.get(clientId);
    return client ? client.adminRole || null : null;
}
function handleAdminStatus(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const nodes = Array.from(fullNodes.values());
    const bestNode = nodes.length > 0
        ? nodes.reduce((a, b) => a.info.chainHeight >= b.info.chainHeight ? a : b)
        : null;
    const status = {
        nodeCount: fullNodes.size,
        clientCount: clients.size,
        chainHeight: bestNode?.info.chainHeight || 0,
        difficulty: 1,
        latestBlock: null
    };
    sendWS(client.ws, { type: 'admin_status', data: status });
}
function handleAdminNodes(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const nodeList = Array.from(fullNodes.values()).map(conn => conn.info);
    sendWS(client.ws, {
        type: 'admin_nodes',
        data: { nodes: nodeList }
    });
}
function handleAdminGetKeys(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認��が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const keysData = trustManager.getTrustedKeysFile();
    sendWS(client.ws, {
        type: 'admin_trusted_keys',
        data: keysData
    });
}
function handleAdminGetAccount(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const address = packet.data.address;
    relayToNode({
        type: 'get_balance',
        data: {
            address,
            clientId,
            adminRequest: true
        }
    });
}
function handleAdminGetBlocks(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const limit = packet.data.limit || 10;
    relayToNode({
        type: 'get_chain',
        data: {
            from: -limit,
            to: 0,
            clientId,
            admin: true
        }
    });
}
function handleAdminMempool(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    relayToNode({
        type: 'get_mempool',
        data: { clientId }
    });
}
function handleAdminGetTransactions(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    const client = clients.get(clientId);
    if (!client)
        return;
    const limit = packet.data.limit || 50;
    relayToNode({
        type: 'get_recent_transactions',
        data: {
            limit,
            clientId
        }
    });
}
async function handleAdminRemoveKey(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_remove_key_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { publicKey, removedBy } = packet.data;
    const client = clients.get(clientId);
    if (!client)
        return;
    const success = trustManager.removeMember(publicKey, removedBy);
    sendWS(client.ws, {
        type: 'admin_remove_key_result',
        data: { success }
    });
    if (success) {
        const keysData = trustManager.getTrustedKeysFile();
        broadcastToNodes({ type: 'sync_trusted_keys', data: keysData });
        broadcastToSeeds({ type: 'sync_trusted_keys', data: keysData });
    }
}
async function handleAdminMint(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_mint_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { address, amount } = packet.data;
    log('Admin', `コイン発行: ${address} に ${amount} BTR`);
    relayToNode({
        type: 'admin_mint',
        data: { address, amount, clientId }
    });
}
async function handleAdminDistribute(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_distribute_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { distributions } = packet.data;
    log('Admin', `一括配給: ${distributions.length} 件`);
    relayToNode({
        type: 'admin_distribute',
        data: { distributions, clientId }
    });
}
async function handleAdminClearMempool(clientId) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_clear_mempool_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    log('Admin', 'Mempool全消去リクエスト');
    relayToNode({
        type: 'admin_clear_mempool',
        data: { clientId }
    });
}
async function handleAdminRemoveTx(clientId, packet) {
    if (!isAdminAuthenticated(clientId)) {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'error', data: { message: '認証が必要です' } });
        return;
    }
    if (getAdminRole(clientId) !== 'root') {
        const client = clients.get(clientId);
        if (client)
            sendWS(client.ws, { type: 'admin_remove_tx_result', data: { success: false, message: 'root権限が必要です' } });
        return;
    }
    const { signature } = packet.data;
    log('Admin', `トランザクション削除: ${signature.slice(0, 16)}...`);
    relayToNode({
        type: 'admin_remove_tx',
        data: { signature, clientId }
    });
}
// ============================================================
// 分散乱数
// ============================================================
function startRandomRound() {
    if (!isPrimary)
        return;
    const activeNodes = Array.from(fullNodes.values()).map(n => n.info);
    const result = randomManager.startRound(activeNodes);
    if (result.fallback) {
        broadcastRandomResult();
        return;
    }
    for (const nodeId of result.selectedNodes) {
        const conn = fullNodes.get(nodeId);
        if (conn)
            sendTCP(conn.socket, { type: 'random_request' });
    }
    setTimeout(() => {
        randomManager.handleTimeout();
        if (randomManager.getPhase() === 'idle')
            broadcastRandomResult();
    }, CONFIG.RANDOM_TIMEOUT);
}
function handleRandomCommit(nodeId, packet) {
    const allCommitted = randomManager.receiveCommit(nodeId, packet.data.hash);
    if (allCommitted) {
        for (const [id, conn] of fullNodes) {
            if (randomManager['selectedNodes'].includes(id))
                sendTCP(conn.socket, { type: 'random_reveal_request' });
        }
    }
}
function handleRandomReveal(nodeId, packet) {
    if (randomManager.receiveReveal(nodeId, packet.data.value))
        broadcastRandomResult();
}
function broadcastRandomResult() {
    const random = randomManager.getCurrentRandom();
    const packet = { type: 'random_result', data: { random } };
    broadcastToNodes(packet);
    broadcastToClients(packet);
    broadcastToSeeds(packet);
    log('Random', `共通乱数配布: ${random.slice(0, 16)}...`);
}
// ============================================================
// ハートビート
// ============================================================
function startHeartbeat() {
    setInterval(() => {
        const now = Date.now();
        for (const [nodeId, conn] of fullNodes) {
            if (now - conn.info.lastPing > CONFIG.HEARTBEAT_TIMEOUT) {
                log('Heartbeat', `タイムアウト: ${nodeId}`);
                conn.socket.destroy();
                fullNodes.delete(nodeId);
                broadcastToNodes({ type: 'node_left', data: { id: nodeId } });
                continue;
            }
            sendTCP(conn.socket, { type: 'ping', timestamp: now });
        }
    }, CONFIG.HEARTBEAT_INTERVAL);
}
// ============================================================
// 定期タスク
// ============================================================
function startPeriodicTasks() {
    setInterval(startRandomRound, CONFIG.RANDOM_INTERVAL);
    setTimeout(startRandomRound, 5000);
    setInterval(() => {
        const p = isPrimary ? '★PRIMARY' : 'SECONDARY';
        log('Stats', `[${p}] ノード: ${fullNodes.size}, クライアント: ${clients.size}, シード: ${seedPeers.size}`);
    }, 30000);
}
// ============================================================
// エントリーポイント ★変更箇所
// ============================================================
function main() {
    console.log('========================================');
    console.log('  BTR (Buturi Coin) Seed Node');
    console.log('========================================');
    trustManager = new TrustManager(CONFIG.ROOT_PUBLIC_KEY);
    randomManager = new RandomManager();
    // --- ★ 初回配布対応: latest_update.json が無ければ node.js から自動生成 ---
    const latestCodePath = path.resolve('./latest_update.json');
    if (fs.existsSync(latestCodePath)) {
        try {
            latestNodeCode = JSON.parse(fs.readFileSync(latestCodePath, 'utf-8'));
            log('Init', `最新コード読み込み: v${latestNodeCode?.version}`);
        }
        catch (e) {
            log('Init', '最新コード読み込み失敗');
        }
    }
    else {
        const nodeJsPath = path.resolve('./node.js');
        if (fs.existsSync(nodeJsPath)) {
            try {
                const code = fs.readFileSync(nodeJsPath, 'utf-8');
                const hash = createHash('sha256').update(code).digest('hex');
                latestNodeCode = {
                    version: '0.0.1',
                    code,
                    hash,
                    signer: '',
                    signature: '',
                };
                fs.writeFileSync(latestCodePath, JSON.stringify(latestNodeCode, null, 2));
                log('Init', `node.js から初回配布パッケージ自動生成: v0.0.1`);
            }
            catch (e) {
                log('Init', `node.js 読み込み失敗: ${e}`);
            }
        }
        else {
            log('Init', '⚠ latest_update.json も node.js も見つかりません');
        }
    }
    // --- ★ ここまで ---
    startTCPServer();
    startWSSServer();
    startSeedServer();
    startHeartbeat();
    startSeedHeartbeat();
    startPeriodicTasks();
    connectToSeeds();
    log('Init', 'シードノード起動完了');
    log('Init', `ホスト: ${getMyHost()}`);
    log('Init', `ポート: TCP=${CONFIG.TCP_PORT}, WSS=${CONFIG.WSS_PORT}/${CONFIG.WSS_DEV_PORT}, Seed=${CONFIG.SEED_PORT}`);
}
main();
//# sourceMappingURL=index.js.map