// ============================================================
// BTR (Buturi Coin) - シードサーバー v3.0
// 完全P2P: admin廃止、ROOT_KEY廃止、メッシュネットワーク
// ============================================================

import net from 'net';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer as createHTTPSServer } from 'https';
import { createServer as createHTTPServer, IncomingMessage, ServerResponse } from 'http';
import fs from 'fs';
import https from 'https';

// ============================================================
// プロトコル共通
// ============================================================

const DELIMITER = '\nLINE_BREAK\n';

interface Packet {
  type: string;
  data?: any;
  timestamp?: number;
  ttl?: number;  // ブロック伝搬ホップ制限
}

function serializePacket(packet: Packet): string {
  return JSON.stringify(packet) + DELIMITER;
}

function sendTCP(socket: net.Socket, packet: Packet): void {
  try { socket.write(serializePacket(packet)); } catch {}
}

function sendWS(ws: WebSocket, packet: Packet): void {
  try { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(packet)); } catch {}
}

// ============================================================
// パケットバッファ
// ============================================================

class PacketBuffer {
  private buffer = '';

  feed(data: string): Packet[] {
    this.buffer += data;
    const packets: Packet[] = [];
    let idx: number;
    while ((idx = this.buffer.indexOf(DELIMITER)) !== -1) {
      const raw = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + DELIMITER.length);
      try { packets.push(JSON.parse(raw)); } catch {}
    }
    // バッファ肥大化防止
    if (this.buffer.length > 10 * 1024 * 1024) this.buffer = '';
    return packets;
  }
}

// ============================================================
// 設定
// ============================================================

interface SeedEntry {
  host: string;
  id: number;
}

interface SeedsFile {
  seeds: SeedEntry[];
}

const CONFIG = {
  TCP_PORT: 5000,             // フルノード用
  WSS_PORT: 443,              // クライアント用 (HTTPS)
  WSS_DEV_PORT: 8443,         // クライアント用 (HTTP, 開発)
  SEED_PORT: 5000,            // シード間接続
  MAX_NODES: 10,              // ノード上限
  HEARTBEAT_INTERVAL: 5000,
  HEARTBEAT_TIMEOUT: 15000,
  BLOCK_HASH_TTL: 60000,      // ブロックハッシュ記憶時間 (1分)
  MAX_TTL: 3,                 // ブロック伝搬最大ホップ
  SSL_CERT: '/etc/letsencrypt/live/shudo-physics.f5.si/fullchain.pem',
  SSL_KEY: '/etc/letsencrypt/live/shudo-physics.f5.si/privkey.pem',
  SEEDS_PATH: './seeds.json',
  SEEDS_CDN: 'https://cdn.jsdelivr.net/gh/ShudoPhysicsClub/FUKKAZHARMAGTOK@main/src/server/fullserver/seeds.json',
  VERSION: '3.0.0',
};

// ============================================================
// 状態管理
// ============================================================

interface FullNodeConnection {
  socket: net.Socket;
  buffer: PacketBuffer;
  info: {
    id: string;
    host: string | undefined;
    connectedAt: number;
    lastPing: number;
    chainHeight: number;
    difficulty: number;
  };
}

interface ClientConnection {
  ws: WebSocket;
  id: string;
  connectedAt: number;
}

interface SeedPeerConnection {
  socket: net.Socket;
  buffer: PacketBuffer;
  host: string;
  seedId: number;
  lastPing: number;
}

const fullNodes: Map<string, FullNodeConnection> = new Map();
const clients: Map<string, ClientConnection> = new Map();
const seedPeers: Map<string, SeedPeerConnection> = new Map();

// ブロック伝搬重複抑止
const seenBlockHashes: Map<string, number> = new Map();

let seeds: SeedEntry[] = [];
let mySeedId: number = -1;
let nodeIdCounter = 0;
let clientIdCounter = 0;

function generateId(prefix: string): string {
  const counter = prefix === 'node' ? ++nodeIdCounter : ++clientIdCounter;
  return `${prefix}_${Date.now()}_${counter}`;
}

function log(category: string, message: string): void {
  const time = new Date().toISOString().slice(11, 19);
  console.log(`[${time}][${category}] ${message}`);
}

// ============================================================
// ブロック伝搬重複抑止
// ============================================================

function isBlockSeen(hash: string): boolean {
  return seenBlockHashes.has(hash);
}

function markBlockSeen(hash: string): void {
  seenBlockHashes.set(hash, Date.now());
}

// 古いエントリ削除
setInterval(() => {
  const now = Date.now();
  for (const [hash, time] of seenBlockHashes) {
    if (now - time > CONFIG.BLOCK_HASH_TTL) seenBlockHashes.delete(hash);
  }
}, 30000);

// ============================================================
// seeds.json
// ============================================================

async function fetchSeedsFromCDN(): Promise<SeedEntry[]> {
  return new Promise((resolve, reject) => {
    log('Seeds', `📡 CDNからseeds.json取得中...`);
    https.get(CONFIG.SEEDS_CDN, (res) => {
      let data = '';
      res.on('data', (chunk: string) => { data += chunk; });
      res.on('end', () => {
        try {
          const file: SeedsFile = JSON.parse(data);
          fs.writeFileSync(CONFIG.SEEDS_PATH, JSON.stringify(file, null, 2));
          log('Seeds', `✅ CDN取得成功: ${file.seeds.length}件`);
          resolve(file.seeds);
        } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function loadSeedsLocal(): SeedEntry[] {
  try {
    if (fs.existsSync(CONFIG.SEEDS_PATH)) {
      const file: SeedsFile = JSON.parse(fs.readFileSync(CONFIG.SEEDS_PATH, 'utf-8'));
      return file.seeds;
    }
  } catch {}
  return [];
}

function getMyHost(): string {
  return process.env.SEED_HOST || '';
}

// ============================================================
// シード間メッシュ接続
// CDNからリスト取得、自分以外のランダム1つに接続
// ============================================================

async function connectToRandomSeed(): Promise<void> {
  // CDNから最新取得
  try {
    seeds = await fetchSeedsFromCDN();
  } catch {
    log('Seeds', `⚠ CDN失敗、ローカルキャッシュ使用`);
    seeds = loadSeedsLocal();
  }

  if (seeds.length === 0) {
    log('Seeds', `❌ シードリストが空`);
    return;
  }

  const myHost = getMyHost();
  const mySeed = seeds.find(s => s.host === myHost);
  if (mySeed) {
    mySeedId = mySeed.id;
    log('Seeds', `自ノード検出: id=${mySeedId} host=${myHost}`);
  }

  // 自分以外のシードからランダムに1つ選択
  const others = seeds.filter(s => s.host !== myHost);
  if (others.length === 0) {
    log('Seeds', `他のシードなし（単独運用）`);
    return;
  }

  const target = others[Math.floor(Math.random() * others.length)];
  log('Seeds', `→ ランダム接続先: ${target.host}:${CONFIG.SEED_PORT} (id=${target.id})`);
  connectToSeed(target);
}

function connectToSeed(seed: SeedEntry): void {
  if (seedPeers.has(seed.host)) return;

  const socket = net.connect(CONFIG.SEED_PORT, seed.host, () => {
    log('Seeds', `✅ シード接続成功: ${seed.host}`);
    const buffer = new PacketBuffer();
    const conn: SeedPeerConnection = {
      socket, buffer,
      host: seed.host,
      seedId: seed.id,
      lastPing: Date.now(),
    };
    seedPeers.set(seed.host, conn);

    sendTCP(socket, { type: 'seed_hello', data: { host: getMyHost(), seedId: mySeedId } });

    socket.on('data', (data) => {
      const packets = buffer.feed(data.toString());
      for (const packet of packets) handleSeedPacket(seed.host, packet);
    });

    socket.on('close', () => {
      seedPeers.delete(seed.host);
      log('Seeds', `❌ シード切断: ${seed.host} → 別シードに再接続`);
      // 切断→別のランダムなシードへ（指数バックオフ付き）
      reconnectToRandomSeed(1000);
    });

    socket.on('error', (err) => {
      log('Seeds', `⚠ シードエラー (${seed.host}): ${err.message}`);
    });
  });

  socket.on('error', (err) => {
    log('Seeds', `❌ シード接続失敗 (${seed.host}): ${err.message}`);
    reconnectToRandomSeed(1000);
  });
}

let reconnectDelay = 1000;
function reconnectToRandomSeed(baseDelay: number): void {
  const delay = Math.min(reconnectDelay, 20000); // 最大20秒
  reconnectDelay = Math.min(reconnectDelay * 2, 20000);
  log('Seeds', `${delay / 1000}秒後に別シードへ再接続...`);
  setTimeout(async () => {
    const myHost = getMyHost();
    const others = seeds.filter(s => s.host !== myHost && !seedPeers.has(s.host));
    if (others.length > 0) {
      const target = others[Math.floor(Math.random() * others.length)];
      connectToSeed(target);
    } else {
      // 全部接続済みor自分だけ → CDN再取得
      await connectToRandomSeed();
    }
  }, delay);
}

// ============================================================
// シード間TCPサーバー（着信側）
// ============================================================

function startSeedServer(): void {
  const server = net.createServer((socket) => {
    const buffer = new PacketBuffer();
    let peerHost = socket.remoteAddress || 'unknown';

    socket.on('data', (data) => {
      const packets = buffer.feed(data.toString());
      for (const packet of packets) {
        if (packet.type === 'seed_hello' && packet.data?.host) {
          peerHost = packet.data.host;
          if (!seedPeers.has(peerHost)) {
            seedPeers.set(peerHost, {
              socket, buffer,
              host: peerHost,
              seedId: packet.data.seedId ?? -1,
              lastPing: Date.now(),
            });
            log('Seeds', `✅ シード着信登録: ${peerHost} (id=${packet.data.seedId})`);
            reconnectDelay = 1000; // リセット
          }
        }
        handleSeedPacket(peerHost, packet);
      }
    });

    socket.on('close', () => {
      seedPeers.delete(peerHost);
      log('Seeds', `❌ シード着信切断: ${peerHost}`);
    });

    socket.on('error', (err) => {
      log('Seeds', `⚠ シード着信エラー (${peerHost}): ${err.message}`);
    });
  });

  // SEED_PORTはTCP_PORTと同じ(5000)なのでstartTCPServerと統合が必要
  // → 別ポートにするか、同一サーバーで判別する
  // ここではSEED_PORT == TCP_PORTなので、startTCPServer内でseed_helloで判別する
  // startSeedServerは独立ポートが必要な場合のみ使う
  // 今回はTCP_PORT=5000でノードもシードも受ける
}

// ============================================================
// シード間パケットハンドリング
// ============================================================

function handleSeedPacket(peerHost: string, packet: Packet): void {
  const conn = seedPeers.get(peerHost);

  switch (packet.type) {
    case 'seed_hello':
      break;
    case 'ping':
      if (conn) { conn.lastPing = Date.now(); sendTCP(conn.socket, { type: 'pong' }); }
      break;
    case 'pong':
      if (conn) conn.lastPing = Date.now();
      break;
    case 'block_broadcast': {
      const hash = packet.data?.hash;
      if (hash && isBlockSeen(hash)) break; // 重複抑止
      if (hash) markBlockSeen(hash);

      // TTLチェック
      const ttl = (packet.ttl ?? CONFIG.MAX_TTL) - 1;
      if (ttl <= 0) break;

      // 自分の配下ノード・クライアントに配信
      broadcastToNodes({ ...packet, ttl });
      broadcastToClients({ type: 'new_block', data: packet.data });
      log('Seeds', `🔲 ブロック中継: height=${packet.data?.height} from ${peerHost} (TTL=${ttl})`);
      break;
    }
    case 'tx_broadcast': {
      broadcastToNodes(packet);
      broadcastToClients({ type: 'new_tx', data: { count: 1 } });
      break;
    }
    case 'difficulty_update': {
      broadcastToClients(packet);
      break;
    }
    case 'random_request': {
      // 乱数リクエストを配下ノードに転送
      broadcastToNodes(packet);
      break;
    }
    case 'random_reveal_request': {
      broadcastToNodes(packet);
      break;
    }
    case 'random_result': {
      broadcastToNodes(packet);
      broadcastToClients(packet);
      break;
    }
    default:
      if (packet.type !== 'ping' && packet.type !== 'pong') {
        log('Seeds', `❓ 不明なシード間パケット: ${packet.type} from ${peerHost}`);
      }
  }
}

// ============================================================
// TCPサーバー（フルノード用 + シード着信 :5000）
// ============================================================

function startTCPServer(): void {
  const server = net.createServer((socket) => {
    const buffer = new PacketBuffer();
    let isSeedPeer = false;
    let peerHost = socket.remoteAddress || 'unknown';

    // まず最初のパケットで判別
    socket.on('data', (data) => {
      const packets = buffer.feed(data.toString());
      for (const packet of packets) {
        // シードからのseed_helloならシード接続として扱う
        if (packet.type === 'seed_hello' && !isSeedPeer) {
          isSeedPeer = true;
          peerHost = packet.data?.host || peerHost;
          if (!seedPeers.has(peerHost)) {
            seedPeers.set(peerHost, {
              socket, buffer,
              host: peerHost,
              seedId: packet.data?.seedId ?? -1,
              lastPing: Date.now(),
            });
            log('Seeds', `✅ シード着信: ${peerHost} (id=${packet.data?.seedId})`);
            reconnectDelay = 1000;
          }
          handleSeedPacket(peerHost, packet);
          continue;
        }

        if (isSeedPeer) {
          handleSeedPacket(peerHost, packet);
        } else {
          // ノード接続（初回registerで登録）
          if (packet.type === 'register' && !fullNodes.has(peerHost + ':' + socket.remotePort)) {
            // ノード上限チェック
            if (fullNodes.size >= CONFIG.MAX_NODES) {
              sendTCP(socket, { type: 'error', data: { message: 'ノード上限に達しています' } });
              socket.destroy();
              return;
            }
            const nodeId = generateId('node');
            const conn: FullNodeConnection = {
              socket, buffer,
              info: {
                id: nodeId,
                host: socket.remoteAddress,
                connectedAt: Date.now(),
                lastPing: Date.now(),
                chainHeight: packet.data?.chainHeight || 0,
                difficulty: packet.data?.difficulty || 1,
              }
            };
            fullNodes.set(nodeId, conn);
            log('TCP', `フルノード接続: ${nodeId} (${socket.remoteAddress}) [${fullNodes.size}/${CONFIG.MAX_NODES}]`);

            // ノードリスト送信
            sendTCP(socket, {
              type: 'node_list',
              data: { nodes: Array.from(fullNodes.values()).map(n => ({ id: n.info.id, host: n.info.host, chainHeight: n.info.chainHeight })) }
            });

            // チェーン同期
            const otherNodes = Array.from(fullNodes.entries()).filter(([id]) => id !== nodeId);
            if (otherNodes.length > 0) {
              const best = otherNodes.reduce((a, b) => a[1].info.chainHeight >= b[1].info.chainHeight ? a : b);
              if (best[1].info.chainHeight > conn.info.chainHeight) {
                sendTCP(best[1].socket, {
                  type: 'send_chain_to',
                  data: { targetNodeId: nodeId, fromHeight: conn.info.chainHeight }
                });
                log('TCP', `チェーン同期依頼: ${best[0]} → ${nodeId}`);
              }
            }

            // このソケットを以後nodeIdで管理するためにクロージャ内変数を設定
            (socket as any).__nodeId = nodeId;
            broadcastToNodes({ type: 'new_node', data: { id: nodeId, host: socket.remoteAddress } }, nodeId);
          }

          const nodeId = (socket as any).__nodeId as string | undefined;
          if (nodeId) {
            handleNodePacket(nodeId, packet);
          }
        }
      }
    });

    socket.on('close', () => {
      if (isSeedPeer) {
        seedPeers.delete(peerHost);
        log('Seeds', `❌ シード切断（着信側）: ${peerHost}`);
      } else {
        const nodeId = (socket as any).__nodeId;
        if (nodeId && fullNodes.has(nodeId)) {
          fullNodes.delete(nodeId);
          log('TCP', `フルノード切断: ${nodeId} [${fullNodes.size}/${CONFIG.MAX_NODES}]`);
          broadcastToNodes({ type: 'node_left', data: { id: nodeId } });
        }
      }
    });

    socket.on('error', (err) => {
      log('TCP', `エラー: ${err.message}`);
    });
  });

  server.listen(CONFIG.TCP_PORT, () => {
    log('TCP', `TCPサーバー起動: port ${CONFIG.TCP_PORT} (ノード+シード兼用)`);
  });
}

// ============================================================
// WSSサーバー（クライアント用 :443 / :8443）+ エクスプローラAPI
// ============================================================

function handleExplorerAPI(req: IncomingMessage, res: ServerResponse): boolean {
  if (!req.url?.startsWith('/api/')) return false;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const url = req.url;

  if (url === '/api/status') {
    const nodes = Array.from(fullNodes.values());
    const bestNode = nodes.length > 0
      ? nodes.reduce((a, b) => a.info.chainHeight >= b.info.chainHeight ? a : b)
      : null;
    res.end(JSON.stringify({
      version: CONFIG.VERSION,
      nodes: fullNodes.size,
      clients: clients.size,
      seedPeers: seedPeers.size,
      chainHeight: bestNode?.info.chainHeight || 0,
      difficulty: bestNode?.info.difficulty || 1,
      mySeedId,
      uptime: process.uptime(),
    }));
    return true;
  }

  if (url === '/api/nodes') {
    const nodeList = Array.from(fullNodes.values()).map(n => ({
      id: n.info.id,
      host: n.info.host,
      chainHeight: n.info.chainHeight,
      difficulty: n.info.difficulty,
      connectedAt: n.info.connectedAt,
    }));
    res.end(JSON.stringify({ nodes: nodeList }));
    return true;
  }

  if (url === '/api/seeds') {
    const seedList = Array.from(seedPeers.values()).map(s => ({
      host: s.host,
      seedId: s.seedId,
      lastPing: s.lastPing,
    }));
    res.end(JSON.stringify({ seeds: seedList, mySeedId }));
    return true;
  }

  // ブロック取得はノードに中継
  if (url?.startsWith('/api/block/')) {
    const heightStr = url.split('/api/block/')[1];
    const height = parseInt(heightStr);
    if (isNaN(height)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid height' }));
      return true;
    }
    // ノードにリクエストして返す（簡易版: 一番高いノードに聞く）
    const nodes = Array.from(fullNodes.values());
    if (nodes.length === 0) {
      res.statusCode = 503;
      res.end(JSON.stringify({ error: 'No nodes available' }));
      return true;
    }
    const best = nodes.reduce((a, b) => a.info.chainHeight >= b.info.chainHeight ? a : b);
    const reqId = `api_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    // 一時的にHTTPレスポンスを保持
    (globalThis as any).__pendingAPI = (globalThis as any).__pendingAPI || new Map();
    (globalThis as any).__pendingAPI.set(reqId, { res, timeout: setTimeout(() => {
      (globalThis as any).__pendingAPI.delete(reqId);
      if (!res.writableEnded) {
        res.statusCode = 504;
        res.end(JSON.stringify({ error: 'Timeout' }));
      }
    }, 5000) });
    sendTCP(best.socket, { type: 'get_block', data: { height, clientId: reqId } });
    return true;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: 'Not found' }));
  return true;
}

function startWSSServer(): void {
  let httpServer: any;

  const requestHandler = (req: IncomingMessage, res: ServerResponse) => {
    if (!handleExplorerAPI(req, res)) {
      res.statusCode = 404;
      res.end('BTR Seed Server');
    }
  };

  if (fs.existsSync(CONFIG.SSL_CERT) && fs.existsSync(CONFIG.SSL_KEY)) {
    httpServer = createHTTPSServer({
      cert: fs.readFileSync(CONFIG.SSL_CERT),
      key: fs.readFileSync(CONFIG.SSL_KEY),
    }, requestHandler);
    httpServer.listen(CONFIG.WSS_PORT, () => {
      log('WSS', `WSSサーバー起動: port ${CONFIG.WSS_PORT} (HTTPS)`);
    });
  } else {
    httpServer = createHTTPServer(requestHandler);
    httpServer.listen(CONFIG.WSS_DEV_PORT, () => {
      log('WSS', `WSサーバー起動: port ${CONFIG.WSS_DEV_PORT} (HTTP, 開発)`);
    });
  }

  const wss = new WebSocketServer({ server: httpServer });
  wss.on('connection', (ws) => {
    const clientId = generateId('client');
    const conn: ClientConnection = { ws, id: clientId, connectedAt: Date.now() };
    clients.set(clientId, conn);
    log('WSS', `クライアント接続: ${clientId} [${clients.size}]`);

    // バージョンハンドシェイク
    sendWS(ws, { type: 'hello', data: { version: CONFIG.VERSION, seedId: mySeedId } });

    ws.on('message', (data) => {
      try {
        const packet: Packet = JSON.parse(data.toString());
        handleClientPacket(clientId, packet);
      } catch {}
    });
    ws.on('close', () => {
      clients.delete(clientId);
      log('WSS', `クライアント切断: ${clientId} [${clients.size}]`);
    });
    ws.on('error', (err) => log('WSS', `エラー (${clientId}): ${err.message}`));
  });
}

// ============================================================
// ノードパケットハンドリング
// ============================================================

function handleNodePacket(nodeId: string, packet: Packet): void {
  const conn = fullNodes.get(nodeId);
  if (!conn) return;

  switch (packet.type) {
    case 'pong':
      conn.info.lastPing = Date.now();
      break;

    case 'register':
      // 既にstartTCPServer内で処理済み
      break;

    case 'height':
      conn.info.chainHeight = packet.data?.height || 0;
      if (packet.data?.difficulty) conn.info.difficulty = packet.data.difficulty;
      if (packet.data?.clientId) {
        const client = clients.get(packet.data.clientId);
        if (client) sendWS(client.ws, packet);
      }
      break;

    case 'block_broadcast': {
      const hash = packet.data?.hash;
      if (hash && isBlockSeen(hash)) break;
      if (hash) markBlockSeen(hash);

      const ttl = (packet.ttl ?? CONFIG.MAX_TTL) - 1;

      // 他ノードに配信
      broadcastToNodes(packet, nodeId);

      // シードピアに転送（TTLあればy
      if (ttl > 0) {
        broadcastToSeeds({ ...packet, ttl });
      }

      // クライアントに通知
      broadcastToClients({ type: 'new_block', data: packet.data });
      break;
    }

    case 'tx_broadcast':
      broadcastToNodes(packet, nodeId);
      broadcastToSeeds(packet);
      broadcastToClients({ type: 'new_tx', data: { count: 1 } });
      break;

    case 'block_accepted': {
      broadcastToClients({ type: 'new_block', data: packet.data });
      if (packet.data?.minerId) {
        const client = clients.get(packet.data.minerId);
        if (client) sendWS(client.ws, { type: 'block_accepted', data: packet.data });
      }
      break;
    }

    case 'block_rejected': {
      if (packet.data?.minerId) {
        const client = clients.get(packet.data.minerId);
        if (client) sendWS(client.ws, { type: 'block_rejected', data: packet.data });
      }
      break;
    }

    case 'difficulty_update': {
      broadcastToClients(packet);
      log('TCP', `難易度更新: diff=${packet.data?.difficulty}`);
      break;
    }

    // ノード→クライアント中継系
    case 'balance': case 'chain': case 'chain_chunk': case 'chain_sync_done':
    case 'token_info': case 'tokens_list': case 'rate': case 'tx_result': case 'block_template':
    case 'mempool': case 'transactions': case 'block': {
      if (packet.data?.clientId) {
        // エクスプローラAPI用
        const pendingAPI = (globalThis as any).__pendingAPI;
        if (pendingAPI && pendingAPI.has(packet.data.clientId)) {
          const { res, timeout } = pendingAPI.get(packet.data.clientId);
          clearTimeout(timeout);
          pendingAPI.delete(packet.data.clientId);
          if (!res.writableEnded) {
            res.end(JSON.stringify(packet.data));
          }
          break;
        }
        const client = clients.get(packet.data.clientId);
        if (client) sendWS(client.ws, packet);
      }
      break;
    }

    // チェーン同期中継
    case 'chain_sync': {
      const targetId = packet.data?.targetNodeId;
      if (targetId) {
        const target = fullNodes.get(targetId);
        if (target) {
          sendTCP(target.socket, {
            type: 'chain_sync',
            data: {
              blocks: packet.data.blocks,
              chunkIndex: packet.data.chunkIndex,
              totalChunks: packet.data.totalChunks,
              totalHeight: packet.data.totalHeight,
            }
          });
        }
      }
      break;
    }

    case 'request_chain': {
      const fromHeight: number = packet.data?.fromHeight || 0;
      const otherNodes = Array.from(fullNodes.entries()).filter(([id]) => id !== nodeId);
      if (otherNodes.length > 0) {
        const best = otherNodes.reduce((a, b) => a[1].info.chainHeight >= b[1].info.chainHeight ? a : b);
        if (best[1].info.chainHeight > fromHeight) {
          sendTCP(best[1].socket, {
            type: 'send_chain_direct',
            data: { targetNodeId: nodeId, fromHeight }
          });
        } else {
          sendTCP(conn.socket, { type: 'chain_sync_response', data: { blocks: [] } });
        }
      } else {
        sendTCP(conn.socket, { type: 'chain_sync_response', data: { blocks: [] } });
      }
      break;
    }

    case 'chain_sync_direct': {
      const targetId = packet.data?.targetNodeId;
      if (targetId) {
        const target = fullNodes.get(targetId);
        if (target) {
          sendTCP(target.socket, { type: 'chain_sync_response', data: { blocks: packet.data.blocks } });
        }
      }
      break;
    }

    case 'check_sync': {
      const myHeight: number = packet.data?.height || 0;
      const otherNodes = Array.from(fullNodes.entries()).filter(([id]) => id !== nodeId);
      if (otherNodes.length > 0) {
        const best = otherNodes.reduce((a, b) => a[1].info.chainHeight >= b[1].info.chainHeight ? a : b);
        if (best[1].info.chainHeight > myHeight + 1) {
          sendTCP(best[1].socket, {
            type: 'send_chain_to',
            data: { targetNodeId: nodeId, fromHeight: myHeight }
          });
          sendTCP(conn.socket, { type: 'sync_needed', data: { bestHeight: best[1].info.chainHeight } });
        }
      }
      break;
    }

    // 乱数 (commit/reveal はノード→シード→仕切り役シードに転送)
    case 'random_commit':
    case 'random_reveal':
      broadcastToSeeds(packet);
      break;

    default:
      if (packet.type !== 'ping') {
        log('TCP', `不明なパケット: ${packet.type} from ${nodeId}`);
      }
  }
}

// ============================================================
// クライアントパケットハンドリング（admin系全廃）
// ============================================================

function handleClientPacket(clientId: string, packet: Packet): void {
  const conn = clients.get(clientId);
  if (!conn) return;

  switch (packet.type) {
    case 'mine':
    case 'block_broadcast':
      broadcastToNodes({ type: 'block_broadcast', data: { ...packet.data, minerId: clientId } });
      break;

    case 'tx':
      relayToNode({ type: 'tx', data: { ...packet.data, clientId } });
      break;

    case 'get_balance': case 'get_chain': case 'get_height':
    case 'get_token': case 'get_rate': case 'get_block_template':
    case 'get_tokens_list': case 'get_mempool':
    case 'get_recent_transactions': case 'get_block':
      relayToNode({ type: packet.type, data: { ...packet.data, clientId } });
      break;

    default:
      log('WSS', `不明なパケット: ${packet.type} from ${clientId}`);
  }
}

// ============================================================
// 中継ヘルパー
// ============================================================

function broadcastToNodes(packet: Packet, excludeId?: string): void {
  for (const [id, conn] of fullNodes) {
    if (id !== excludeId) sendTCP(conn.socket, packet);
  }
}

function broadcastToClients(packet: Packet): void {
  for (const [, conn] of clients) sendWS(conn.ws, packet);
}

function broadcastToSeeds(packet: Packet): void {
  for (const [, conn] of seedPeers) sendTCP(conn.socket, packet);
}

function relayToNode(packet: Packet): void {
  const nodes = Array.from(fullNodes.values());
  if (nodes.length === 0) {
    if (packet.data?.clientId) {
      const client = clients.get(packet.data.clientId);
      if (client) sendWS(client.ws, { type: 'error', data: { message: 'フルノードが利用できません' } });
    }
    return;
  }
  const best = nodes.reduce((a, b) => a.info.chainHeight >= b.info.chainHeight ? a : b);
  sendTCP(best.socket, packet);
}

// ============================================================
// ハートビート
// ============================================================

function startHeartbeat(): void {
  setInterval(() => {
    const now = Date.now();

    // ノードのハートビート
    for (const [nodeId, conn] of fullNodes) {
      if (now - conn.info.lastPing > CONFIG.HEARTBEAT_TIMEOUT) {
        log('Heartbeat', `ノードタイムアウト: ${nodeId}`);
        conn.socket.destroy();
        fullNodes.delete(nodeId);
        broadcastToNodes({ type: 'node_left', data: { id: nodeId } });
        continue;
      }
      sendTCP(conn.socket, { type: 'ping', timestamp: now });
    }

    // シードのハートビート
    for (const [host, conn] of seedPeers) {
      if (now - conn.lastPing > CONFIG.HEARTBEAT_TIMEOUT) {
        log('Heartbeat', `シードタイムアウト: ${host}`);
        conn.socket.destroy();
        seedPeers.delete(host);
        reconnectToRandomSeed(1000);
        continue;
      }
      sendTCP(conn.socket, { type: 'ping', timestamp: now });
    }
  }, CONFIG.HEARTBEAT_INTERVAL);
}

// ============================================================
// 定期タスク
// ============================================================

function startPeriodicTasks(): void {
  // 統計表示 30秒
  setInterval(() => {
    log('Stats', `ノード: ${fullNodes.size}/${CONFIG.MAX_NODES}, クライアント: ${clients.size}, シード: ${seedPeers.size}, 既知ブロック: ${seenBlockHashes.size}`);
  }, 30000);

  // シード接続レポート 60秒
  setInterval(() => {
    log('Seeds', `━━━ シード状況 ━━━`);
    if (seedPeers.size === 0) {
      log('Seeds', `⚠ シード接続なし`);
    } else {
      for (const [host, conn] of seedPeers) {
        const ago = Math.floor((Date.now() - conn.lastPing) / 1000);
        log('Seeds', `  ✅ ${host} (id=${conn.seedId}, ping ${ago}秒前)`);
      }
    }
    log('Seeds', `━━━━━━━━━━━━━━━━━━`);
  }, 60000);
}

// ============================================================
// エントリーポイント
// ============================================================

async function main(): Promise<void> {
  console.log('========================================');
  console.log(`  BTR Seed Server v${CONFIG.VERSION}`);
  console.log('  完全P2P - admin権限なし');
  console.log('========================================');

  startTCPServer();
  startWSSServer();
  startHeartbeat();
  startPeriodicTasks();
  await connectToRandomSeed();

  const myHost = getMyHost();
  log('Init', `起動完了`);
  log('Init', `ホスト: ${myHost || '(未設定)'} / ID: ${mySeedId}`);
  log('Init', `ポート: TCP=${CONFIG.TCP_PORT}, WSS=${CONFIG.WSS_PORT}/${CONFIG.WSS_DEV_PORT}`);
  log('Init', `ノード上限: ${CONFIG.MAX_NODES}, ブロックTTL: ${CONFIG.MAX_TTL}`);
}

main();