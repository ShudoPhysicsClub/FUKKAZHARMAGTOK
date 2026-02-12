# BTR (Buturi Coin) ブロックチェーン 最終設計仕様書

## 1. 概要

独自ブロックチェーン。
ネイティブコイン **BTR (Buturi Coin)** と、ユーザーが自由に作成できるトークンシステム、
組み込み型AMM（自動マーケットメイカー）を持つ。

将来の実用化も視野に入れた設計。

---

## 2. ネットワーク構成

### 2.1 シードノード

- ホスト: `mail.shudo-physics.com`（初期）
- 役割:
  - ノード発見（新ノードにノードリストを提供）
  - ノード間通信の中継（TCP）
  - クライアント接続の受付（WSS :443）→ フルノードにTCP中継
  - 分散乱数生成の合図・取りまとめ
  - アップデート配信の中継
  - 管理画面（Web UI）のホスト
  - 最新ノードコードの保持・新ノードへの配布
- チェーンデータは保持しない（軽量）
- SSL証明書: Let's Encrypt

### 2.2 シードノード複数台構成

- シードノード一覧は `seeds.json` で管理（root署名付き）
- `seeds.json` はCDNで配布、root署名で改ざん検知
- シードノード間は常時TCP接続を維持
- プライマリ/セカンダリの役割分担

```json
// seeds.json（root署名付き）
{
  "seeds": [
    { "host": "shudo-physics.f5.si", "priority": 1, "publicKey": "..." },
    { "host": "seed2.example.com", "priority": 2, "publicKey": "..." }
  ],
  "signature": "rootのEd25519署名"
}
```

**seeds.json の検証:**
```typescript
function verifySeedsJson(seedsData: any): boolean {
  const { signature, ...rest } = seedsData;
  return ed25519.verify(canonicalJSON(rest), signature, ROOT_KEY);
}
```

**プライマリ（メイン）:**
- 分散乱数の合図
- ノードリスト管理（マスター）
- アップデート配布の起点

**セカンダリ（サブ）:**
- クライアント/ノードの接続受付・中継
- プライマリ死亡時に自動昇格

**プライマリ選出ルール:**
- `seeds.json` の priority 順（小さい方が優先）
- プライマリ死亡（ハートビート3回連続失敗）→ セカンダリが昇格
- プライマリ復活 → セカンダリに戻る

**シードノード間同期:**
- ノードリスト
- `trusted_keys.json`（メンバー公開鍵）
- 分散乱数の結果
- 最新ノードコード（UpdatePackage）
- ハートビート（5秒間隔）

**seeds.json の更新:**
- root署名が必須（memberでは不可）
- アップデートシステムで全ノードに配布

### 2.3 フルノード（Raspberry Pi）

- 機種: Raspberry Pi 4B、Zero 2W、（将来）Pi 5
- 役割:
  - ブロックチェーンデータの保存
  - トランザクション検証
  - ブロック検証
  - アカウント状態管理
- ポート開放不要（シードノードにアウトバウンド接続するだけ）
- マイニングはしない

### 2.4 クライアント（ブラウザ）

- WSS経由でシードノードに接続 → シードノードがフルノードに中継
- 役割:
  - ウォレット管理（鍵ペア生成、秘密鍵保管）
  - 送金・トークン操作・スワップ
  - マイニング（Web WorkerでPoW計算）
  - ブロック情報閲覧

### 2.5 通信プロトコル

| 経路 | プロトコル |
|------|-----------|
| クライアント → シードノード | WSS (WebSocket Secure) |
| シードノード → フルノード | TCP |
| シードノード ↔ シードノード | TCP（常時接続） |

### 2.6 パケットフォーマット

JSON + 改行 + `LINE_BREAK` + 改行 を区切り文字として使用。

```typescript
const DELIMITER = '\nLINE_BREAK\n';

// 送信
socket.write(JSON.stringify(packet) + DELIMITER);

// 受信
let buffer = '';
socket.on('data', (data) => {
  buffer += data.toString();
  const parts = buffer.split(DELIMITER);
  buffer = parts.pop();
  for (const part of parts) {
    if (part) {
      const packet = JSON.parse(part);
      handlePacket(packet);
    }
  }
});
```

### 2.7 パケット種別

**クライアント → フルノード（シードノード中継）:**
| type | 説明 |
|------|------|
| `tx` | トランザクション送信 |
| `mine` | マイニング結果（新ブロック） |
| `get_balance` | 残高照会 |
| `get_chain` | チェーン取得 |
| `get_height` | チェーンの高さ取得 |
| `get_token` | トークン情報取得 |
| `get_rate` | AMMレート取得 |

**フルノード → クライアント（シードノード中継）:**
| type | 説明 |
|------|------|
| `balance` | 残高返答 |
| `chain` | チェーンデータ |
| `chain_chunk` | チェーンデータ（チャンク） |
| `chain_sync_done` | チェーン同期完了 |
| `height` | チェーン高さ返答 |
| `token_info` | トークン情報 |
| `rate` | AMMレート |
| `new_block` | 新ブロック通知 |
| `tx_result` | トランザクション結果 |

**フルノード ↔ シードノード:**
| type | 説明 |
|------|------|
| `register` | ノード登録 |
| `node_list` | ノードリスト |
| `new_node` | 新ノード通知 |
| `node_left` | ノード離脱通知 |
| `ping` / `pong` | ハートビート |
| `block_broadcast` | 新ブロック伝播 |
| `tx_broadcast` | トランザクション伝播 |

**分散乱数:**
| type | 説明 |
|------|------|
| `random_request` | 乱数提出要求 |
| `random_commit` | hash(乱数)提出 |
| `random_reveal` | 乱数公開 |
| `random_result` | 共通乱数配布 |

**管理系:**
| type | 説明 |
|------|------|
| `update` | コード更新 |
| `add_member` | メンバー追加 |
| `sync_trusted_keys` | 公開鍵リスト同期 |
| `sync_nodelist` | ノードリスト同期 |
| `who_is_primary` | プライマリ問い合わせ |
| `primary_is` | プライマリ返答 |
| `get_seed_list` | シードノードリスト取得 |
| `seed_list` | シードノードリスト返答 |
| `get_latest_files` | 最新ファイル一式要求 |
| `latest_files` | 最新ファイル一式返答 |

### 2.8 ノード発見

1. CDNから `seeds.json` を取得し、root署名を検証
2. 優先度順にシードノードに接続
3. 接続したシードノードからノードリスト取得
4. 失敗時: ローカルキャッシュから前回のピアに接続
5. 最終手段: ローカルネットワークでマルチキャスト探索

### 2.9 接続管理

- 全ノードがシードノードと常時TCP接続
- ハートビート: `ping` / `pong` による定期生存確認
- 切断検出時: 自動再接続

**再接続フロー:**
```
切断検出
  │
  └─ seeds.json読む（ローカルキャッシュ）
      │
      ├─ seed1に再接続 → 成功 → 差分同期 → 完了
      ├─ 失敗 → seed2に接続 → 成功 → 差分同期 → 完了
      └─ 全部失敗 → 5秒待ってリトライ
```

**再接続後の差分同期:**
```typescript
async function syncDiff() {
  const myHeight = getChainHeight();
  const peerHeight = await askHeight(peer);
  
  if (peerHeight > myHeight) {
    await getChainChunk(peer, myHeight + 1, peerHeight);
    validateAndApply();
  }
}
```

### 2.10 チェーン同期（新ノード参加）

**並列同期（優先）:**
```
ノード3台、ブロック900の場合:
  A: 0〜299
  B: 300〜599
  C: 600〜899
→ 3倍速で同期
```

**フォールバック:**
- 並列同期失敗時 → 一番高さの大きいノード1台から全取得

**同期手順:**
1. シードノードからノードリスト取得
2. 全ノードに `get_height` で高さを聞く
3. 一番高いのを基準に、アクティブノードで分担
4. チャンク単位で受信 & ハッシュチェーン検証
5. 同期中の新ブロックはキューに溜める
6. 同期完了後にキューのブロックを適用

### 2.11 新ノード初回起動

新ノードは `launcher.ts` のみを持てばよい（root公開鍵 + CDN URLがハードコード済み）。

```
launcher.ts起動
  │
  ├─ 1. CDNからseeds.json取得
  │     └─ root署名検証
  │
  ├─ 2. 優先度順にシードノードに接続
  │
  ├─ 3. シードノードに最新ファイル要求
  │     { type: 'get_latest_files' }
  │
  ├─ 4. シードノードが返答
  │     {
  │       type: 'latest_files',
  │       data: {
  │         nodeCode: {
  │           version: '1.2.0',
  │           code: '...',
  │           hash: '...',
  │           signer: '...',
  │           signature: '...'
  │         },
  │         trustedKeys: { keys: [...] }
  │       }
  │     }
  │
  ├─ 5. ランチャーが署名検証
  │     ├─ trusted_keys内の公開鍵で署名確認
  │     └─ sha256(code) === hash 確認
  │
  ├─ 6. node.js書き出し + trusted_keys.json保存 + seeds.jsonローカルキャッシュ
  │
  ├─ 7. node.jsをfork
  │
  └─ 8. node.jsがチェーン同期開始
```

**シードノード側の最新コード保持:**
```typescript
let latestNodeCode: UpdatePackage | null = null;

// アップデート受信時に保存
function onUpdate(update: UpdatePackage) {
  if (verifyUpdate(update)) {
    latestNodeCode = update;
    broadcastToNodes(update);
  }
}

// 新ノードからの要求に応答
function onGetLatestFiles(conn: Socket) {
  conn.write(JSON.stringify({
    type: 'latest_files',
    data: {
      nodeCode: latestNodeCode,
      trustedKeys: JSON.parse(readFileSync('./trusted_keys.json', 'utf-8'))
    }
  }) + DELIMITER);
}
```

---

## 3. 暗号技術

### 3.1 署名: Ed25519（自作実装）

- ウォレットの鍵ペア生成
- トランザクション署名・検証
- アップデート署名
- メンバー追加署名

### 3.2 ハッシュ: SHA-256

- ブロックハッシュ
- PoWのnonce探索
- アドレス生成
- 分散乱数合成

### 3.3 ウォレットアドレス

Ed25519公開鍵からSHA-256ハッシュ → 先頭160bit（40文字）

```typescript
function createWallet() {
  const { publicKey, privateKey } = ed25519.generateKeyPair();
  const address = '0x' + sha256(publicKey).slice(0, 40);
  return { publicKey, privateKey, address };
}
```

### 3.4 アドレス体系

| 種類 | 長さ | 形式 | 例 |
|------|------|------|-----|
| ウォレットアドレス | 160bit (42文字) | `0x` + sha256(公開鍵)[:40] | `0xa3f1b2c4d5e6f7089b1c2d3e4f5a6b7c8d9e0f12` |
| トークンアドレス | 64bit (18文字) | `0x` + randomBytes(8) | `0x7a2b9c4d1e5f8a03` |
| BTRアドレス | 64bit (18文字) | 固定 | `0x0000000000000000` |

### 3.5 Canonical JSON（署名の正規化）

署名・検証時にキーをアルファベット順にソートして決定論的なJSON文字列を生成。

```typescript
function canonicalJSON(obj: any): string {
  if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`);
  return '{' + pairs.join(',') + '}';
}
```

---

## 4. アカウントシステム

### 4.1 アカウント構造

アカウントは使われた時に初めて作成される（遅延初期化）。

```typescript
interface Account {
  address: string;
  balance: number;    // BTR残高
  nonce: number;      // 送信トランザクションの連番
  tokens: Map<string, number>;  // トークンアドレス → 残高
}

const accounts: Map<string, Account> = new Map();

function getAccount(address: string): Account {
  if (!accounts.has(address)) {
    accounts.set(address, {
      address,
      balance: 0,
      nonce: 0,
      tokens: new Map()
    });
  }
  return accounts.get(address)!;
}
```

### 4.2 Nonce（リプレイ攻撃対策）

Ethereum方式のアカウントnonceカウンター。

```
送信者のnonce: 0 → 1 → 2 → 3...

最初の送金: nonce = 0 ✅ → nonce が 1 に
次の送金:   nonce = 1 ✅ → nonce が 2 に
同じの再送: nonce = 0 ❌（もう使った）
飛ばす:     nonce = 5 ❌（2が先）
```

使用済みリストの管理が不要でメモリ効率が良い。

---

## 5. トランザクション

### 5.1 トランザクション構造

```typescript
interface Transaction {
  type: 'transfer' | 'create_token' | 'token_transfer' | 'swap' | 'rename_token';
  token: string;          // 対象トークンアドレス（BTR: '0x0000000000000000'）
  from: string;           // 送信者アドレス
  publicKey: string;      // 送信者のEd25519公開鍵（署名検証用）
  to?: string;            // 受信者アドレス
  amount?: number;        // 送金額
  fee: number;            // ガス代（BTR建て、固定 0.5 BTR）
  nonce: number;          // 送信者ごとの連番
  timestamp: number;      // クライアントの時刻（Date.now()）
  signature: string;      // Ed25519署名
  data?: {                // type別の追加データ
    name?: string;
    symbol?: string;
    totalSupply?: number;
    poolRatio?: number;
    distribution?: 'creator' | 'mining' | 'split' | 'airdrop';
    tokenIn?: string;
    tokenOut?: string;
    amountIn?: number;
    minAmountOut?: number;
    newName?: string;
  };
}
```

### 5.2 署名

`signature` フィールドを除いた全フィールドを Canonical JSON 化して署名。

```typescript
function signTransaction(tx: Transaction, privateKey: string): string {
  const { signature, ...rest } = tx;
  const message = canonicalJSON(rest);
  return ed25519.sign(message, privateKey);
}
```

### 5.3 検証

```typescript
function verifyTransaction(tx: Transaction): boolean {
  // 1. 公開鍵からアドレスが正しいか
  if ('0x' + sha256(tx.publicKey).slice(0, 40) !== tx.from) {
    return false;
  }
  
  // 2. 署名が正しいか
  const { signature, ...rest } = tx;
  const message = canonicalJSON(rest);
  if (!ed25519.verify(message, tx.signature, tx.publicKey)) {
    return false;
  }
  
  // 3. タイムスタンプが±10分以内か
  if (Math.abs(Date.now() - tx.timestamp) > 10 * 60 * 1000) {
    return false;
  }
  
  // 4. nonceが正しいか（アカウントの現在のnonceと一致）
  const account = getAccount(tx.from);
  if (tx.nonce !== account.nonce) {
    return false;
  }
  
  return true;
}
```

---

## 6. ブロック

### 6.1 ブロック構造

```typescript
interface Block {
  height: number;              // ブロック番号
  previousHash: string;        // 前ブロックのSHA-256ハッシュ
  timestamp: number;           // 生成時刻
  nonce: number;               // PoW用
  difficulty: number;          // 現在の難易度
  miner: string;               // マイナーのウォレットアドレス
  reward: number;              // このブロックの報酬（80-120 BTR）
  transactions: Transaction[];
  hash: string;                // このブロックのSHA-256ハッシュ
}
```

### 6.2 ブロックサイズ上限

**3MB**（約6000トランザクション/ブロック）

```typescript
const MAX_BLOCK_SIZE = 3 * 1024 * 1024; // 3MB

function createBlock(pendingTxs: Transaction[]): Block {
  const txs: Transaction[] = [];
  let size = 0;
  
  for (const tx of pendingTxs) {
    const txSize = Buffer.byteLength(canonicalJSON(tx));
    if (size + txSize > MAX_BLOCK_SIZE) break;
    txs.push(tx);
    size += txSize;
  }
  
  return { /* ... */ transactions: txs };
}
```

### 6.3 フォーク選択ルール

最長チェーンルール（ビットコインと同じ）。

```typescript
function selectChain(chainA: Block[], chainB: Block[]): Block[] {
  // 長い方が正
  if (chainA.length !== chainB.length) {
    return chainA.length > chainB.length ? chainA : chainB;
  }
  
  // 同じ長さなら累積難易度が高い方
  const diffA = chainA.reduce((sum, b) => sum + b.difficulty, 0);
  const diffB = chainB.reduce((sum, b) => sum + b.difficulty, 0);
  
  return diffA >= diffB ? chainA : chainB;
}
```

負けた側のブロックに入っていたトランザクションは未確認に戻し、次のブロックに再収録。

---

## 7. Proof of Work

### 7.1 マイニング

クライアント（ブラウザ）がWeb WorkerでSHA-256を計算。

```typescript
function mineBlock(block: Block): Block {
  let nonce = 0;
  while (true) {
    block.nonce = nonce;
    const hash = sha256(
      block.previousHash +
      block.timestamp +
      block.nonce +
      block.miner +
      JSON.stringify(block.transactions)
    );
    if (hash.startsWith('0'.repeat(block.difficulty))) {
      block.hash = hash;
      return block;
    }
    nonce++;
  }
}
```

### 7.2 難易度調整

- 目標: **45秒/ブロック**
- 直近 **10ブロック** の平均生成時間で調整
- 平均 < 40秒 → difficulty + 1
- 平均 > 50秒 → difficulty - 1（最低 1）
- マイナー0人 → ブロック生成停止（次のマイナーが来たら再開）

---

## 8. コイン: BTR (Buturi Coin)

### 8.1 パラメータ

| パラメータ | 値 |
|-----------|-----|
| 名前 | Buturi Coin |
| シンボル | BTR |
| トークンアドレス | `0x0000000000000000` |
| 総供給量 | 50億 BTR |
| ブロック時間 | 45秒 |
| ブロック報酬 | 80〜120 BTR（分散乱数で決定、平均100） |
| 1日あたり発行量 | 約192,000 BTR（1920ブロック × 平均100） |
| 枯渇まで | 約68年 |
| ガス代 | 0.5 BTR（固定） |
| トークン作成費 | 10,000 BTR |
| トークン名変更費 | 500 BTR |
| 手数料の行き先 | 全てマイナー（ブロック生成者）へ |

### 8.2 初期配布

事前配布なし。最初のマイナーが最初のブロックを掘ることでBTR経済圏がスタート。

---

## 9. トークンシステム

### 9.1 トークン作成

- 費用: 10,000 BTR（マイナーの報酬として入る）
- トークンアドレス: 64bit乱数 (`crypto.randomBytes(8)`)
- BTRアドレス (`0x0000000000000000`) とは重複しない

### 9.2 配布方式（選択可能）

| 方式 | 説明 |
|------|------|
| `creator` | 全額作成者に渡る |
| `mining` | BTRマイニングと一緒に徐々に発行 |
| `split` | 指定比率で作成者とプールに分配 |
| `airdrop` | 接続中のウォレットに均等配布 |

### 9.3 トークンメタデータ（オンチェーン）

```typescript
interface TokenInfo {
  address: string;            // 0x + 16文字（64bit乱数）
  symbol: string;             // PHY
  name: string;               // PhysicsCoin
  creator: string;            // 作成者の公開鍵
  createdAt: number;
  totalSupply: number;
  poolRatio: number;          // AMMプールに入れる比率
  distribution: 'creator' | 'mining' | 'split' | 'airdrop';
}
```

### 9.4 初期流動性

- トークン作成費の10,000 BTRがそのままAMMプールに入る
- 作成者には `totalSupply × (1 - poolRatio)` が渡る
- プールには `totalSupply × poolRatio` のトークンが入る
- プールはロック（引き出し不可）

### 9.5 トークン名変更

- 費用: 500 BTR
- `rename_token` トランザクションで実行

---

## 10. AMM（自動マーケットメイカー）

### 10.1 基本設計

- 全トークンはBTR建て（BTRが基軸通貨）
- トークン同士の交換: TokenA → BTR → TokenB
- レート = AMM需給 + 分散乱数による揺らぎ（±15%）
- 揺らぎは1分ごとに変化

### 10.2 レート計算

```typescript
function getRate(commonRandom: string, token: string, minute: number): number {
  const base = getAMMRate('BTR', token);
  
  const seed = sha256(commonRandom + token + minute);
  const fluctuation = parseInt(seed.slice(0, 8), 16);
  const change = (fluctuation % 3000 - 1500) / 10000; // ±15%
  
  return base * (1 + change);
}
```

全ノードが同じ共通乱数と同じ式を使うため、同じ瞬間に同じレートが導出される（決定論的）。

### 10.3 トークン間交換

```typescript
function getCrossRate(tokenA: string, tokenB: string): number {
  return rates.get(tokenB) / rates.get(tokenA);
}
```

---

## 11. 分散乱数生成

### 11.1 通常フロー（1時間ごと）

1. プライマリシードノードが合図を送る
2. ランダムに3ノードを選出
3. 選出されたノードがコミットメント `hash(乱数)` を提出
4. 全員出揃ったら乱数を公開（Reveal）
5. シードノードが合成: `sha256(randomA + randomB + randomC)`
6. 共通乱数を全ノード・全クライアントに配布

### 11.2 障害時フォールバック

ノードが3台未満、またはコミット/リビールがタイムアウト（10秒）した場合:
シードノードが自分で乱数を生成して配布。

```typescript
async function generateRandom() {
  const nodes = getActiveNodes();
  
  if (nodes.length >= 3) {
    try {
      const selected = selectRandom(nodes, 3);
      const commits = await requestCommits(selected, 10000);
      const reveals = await requestReveals(selected, 10000);
      return sha256(reveals.join(''));
    } catch {
      // タイムアウト → フォールバック
    }
  }
  
  return sha256(crypto.randomBytes(32).toString('hex') + Date.now());
}
```

### 11.3 用途

- BTRブロック報酬（80〜120）の決定
- 各トークンのブロック報酬の決定
- AMMレートの揺らぎ（±15%）
- コインごとに異なる値を導出: `sha256(commonRandom + tokenSymbol + purpose)`

---

## 12. 権限システム

### 12.1 ロール

| ロール | 説明 |
|--------|------|
| root | 全権限（初期配布、rootだけが追加可能） |
| member | メンバー追加 + アップデート配信 |

### 12.2 権限表

| 操作 | root | member |
|------|------|--------|
| メンバー追加 | ✅ | ✅ |
| root追加 | ✅ | ❌ |
| メンバー削除 | ✅ | ❌ |
| アップデート配信 | ✅ | ✅ |
| seeds.json更新 | ✅ | ❌ |

### 12.3 信頼チェーン

- rootのEd25519公開鍵をランチャーとシードノードのコードにハードコード（信頼の起点）
- メンバー追加時: 追加者がEd25519で新メンバーの公開鍵 + ロールに署名
- メンバーがさらに別のメンバーを追加可能（ツリー構造）

### 12.4 鍵管理

**シードノード:**
- root公開鍵: コードにハードコード
- メンバー公開鍵: `trusted_keys.json` で管理
- シードノード間で `trusted_keys.json` を常に同期
- 最新ノードコード（UpdatePackage）を保持

**フルノード（ラズパイ）:**
- 初回起動時: ランチャーがCDNからseeds.json取得 → シードノードに接続 → 最新ファイル取得
- `trusted_keys.json` もシードノードから取得
- 以降は定期同期

```json
// trusted_keys.json
{
  "keys": [
    { "publicKey": "...", "role": "root", "addedBy": "root", "signature": "..." },
    { "publicKey": "...", "role": "member", "addedBy": "root公開鍵", "signature": "..." },
    { "publicKey": "...", "role": "member", "addedBy": "memberA公開鍵", "signature": "..." }
  ]
}
```

### 12.5 検証

```typescript
function isTrusted(publicKey: string): boolean {
  return publicKey === ROOT_PUBLIC_KEY || trustedKeys.has(publicKey);
}

function canAddRoot(publicKey: string): boolean {
  return getRole(publicKey) === 'root';
}

function canUpdate(publicKey: string): boolean {
  return isTrusted(publicKey);
}

function canUpdateSeeds(publicKey: string): boolean {
  return getRole(publicKey) === 'root';
}
```

---

## 13. アップデートシステム

### 13.1 ランチャー方式

ランチャー（`launcher.ts`）が署名検証とプロセス管理を担当。ランチャー自体は更新しない。
新ノードはランチャーのみを持てばよい（root公開鍵 + CDN URLがハードコード済み）。

```typescript
// launcher.ts（土台、更新不要）
import { fork } from 'child_process';

const ROOT_KEY = 'rootのEd25519公開鍵'; // ハードコード
const CDN_URL = 'https://cdn.example.com/btr/seeds.json'; // ハードコード
const trustedKeys: Map<string, 'root' | 'member'> = new Map();
trustedKeys.set(ROOT_KEY, 'root');

// 起動時にtrusted_keys.jsonからMAP復元（なければシードから取得）
await loadOrFetchTrustedKeys();

function startNode() {
  const node = fork('./node.js');
  node.on('exit', (code) => {
    if (code === 100) {
      startNode();
    } else {
      setTimeout(startNode, 3000);
    }
  });
}

startNode();
```

### 13.2 アップデートパッケージ

```typescript
interface UpdatePackage {
  version: string;
  code: string;         // コード全体（ミニファイ済み、1行）
  hash: string;         // sha256(code)
  signer: string;       // 署名者の公開鍵
  signature: string;    // ed25519.sign(hash, privateKey)
}
```

### 13.3 ランチャーでの検証と適用

```typescript
function onUpdate(update: UpdatePackage) {
  // 1. trusted_keys MAPに署名者がいるか
  if (!trustedKeys.has(update.signer)) return;
  
  // 2. ハッシュが合ってるか
  if (sha256(update.code) !== update.hash) return;
  
  // 3. 署名が正しいか
  if (!ed25519.verify(update.hash, update.signature, update.signer)) return;
  
  // 4. ファイル上書き → 再起動
  writeFileSync('./node.js', update.code);
  process.exit(100);
}
```

### 13.4 Web管理画面からの配信

ブラウザの管理画面から配信可能:
1. コードファイルをアップロード
2. ブラウザ内で秘密鍵を使って署名（秘密鍵はサーバーに送らない）
3. WSSでシードノードに送信
4. シードノードで `trusted_keys.json` を使って署名者確認 & 署名検証
5. OK → 最新コードとして保存 & 全ノードに配布 / NG → 拒否

---

## 14. ジェネシスブロック

```typescript
const genesisBlock = {
  height: 0,
  previousHash: '0x' + '0'.repeat(64),
  timestamp: /* チェーン起動日時 */,
  nonce: 0,
  difficulty: 1,
  miner: '0x' + '0'.repeat(40),
  reward: 0,
  transactions: [],
  hash: /* sha256で計算 */,

  config: {
    name: 'Buturi Coin',
    symbol: 'BTR',
    tokenAddress: '0x0000000000000000',
    totalSupply: 5000000000,
    blockTime: 45,
    blockReward: { min: 80, max: 120 },
    gasFee: 0.5,
    tokenCreationFee: 10000,
    tokenRenameFee: 500,
    timestampTolerance: 600000,   // ±10分
    maxBlockSize: 3145728,        // 3MB
    admin: {
      publicKey: 'rootのEd25519公開鍵',
      address: 'rootのウォレットアドレス',
    }
  },

  message: 'Foooooooooooooooooooo物理班最高!YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA',
};
```

---

## 15. 管理者パネル

### 15.1 概要

管理者パネル (`admin.html`) は、BTRネットワークの監視・管理を行うWebベースのダッシュボード。

- アクセス: `https://shudo-physics.f5.si/admin.html`
- 認証: Ed25519署名ベース（信頼済み鍵のみ）
- ロール: root（全権限）、member（閲覧のみ）

### 15.2 認証方法

1. **秘密鍵の準備**
   - 既存の管理者鍵を使用
   - または「新しい管理者鍵を生成」ボタンで生成
   - 新しい鍵はroot権限で `trusted_keys.json` に追加する必要がある

2. **ログイン**
   - 秘密鍵（64文字のhex）を入力
   - 「認証」ボタンをクリック
   - Ed25519署名でチャレンジレスポンス認証
   - 信頼済み鍵でない場合は認証失敗

### 15.3 機能一覧

#### ダッシュボード
- **ネットワーク概要**
  - 接続ノード数
  - 接続クライアント数
  - チェーン高さ
  - 現在の難易度
- **最新ブロック情報**
  - ブロック高
  - マイナーアドレス
  - トランザクション数
  - タイムスタンプ
- **Mempool状況**
  - 保留中トランザクション数
  - リアルタイム更新

#### ノード管理
- 接続中のフルノード一覧
- ノードID、接続時刻、チェーン高さ、最終Ping
- 自動更新機能

#### 信頼済み鍵管理
- **閲覧**（member/root）
  - 現在の信頼済み鍵一覧
  - 公開鍵、ロール、追加者
- **追加**（member/root）
  - 新しい公開鍵を追加
  - ロール選択（root/member）
  - Ed25519署名で承認
- **削除**（rootのみ）
  - 既存の鍵を削除
  - root権限必須

#### トランザクション監視
- 最近のトランザクション一覧（最大50件）
- トランザクション種別、送信元、宛先、金額、手数料
- タイムスタンプ

#### アカウント検索
- アドレスでアカウント情報を検索
- BTR残高、nonce、トークン残高を表示

#### ブロック履歴
- 最近のブロック一覧（1〜100件）
- ブロック高、ハッシュ、マイナー、Tx数、タイムスタンプ

### 15.4 セキュリティ

- **署名ベース認証**: パスワード不要、Ed25519署名で認証
- **ロールベースアクセス制御**: root/memberで権限分離
- **TrustManager統合**: 既存の信頼管理システムと連携
- **全管理操作の認証**: すべてのAPI呼び出しで認証チェック
- **root専用操作**: 鍵削除などはroot権限必須

### 15.5 使用方法

```bash
# 1. シードノードにアクセス
# ブラウザで https://shudo-physics.f5.si/admin.html を開く

# 2. 管理者鍵で認証
# - 秘密鍵を入力して「認証」
# - または「新しい管理者鍵を生成」で鍵を作成

# 3. 各タブで管理操作
# - ダッシュボード: ネットワーク概要
# - ノード管理: フルノード監視
# - 信頼済み鍵: メンバー管理
# - トランザクション: Tx履歴
# - アカウント検索: 残高確認
# - ブロック履歴: ブロックチェーン閲覧
```

### 15.6 管理者鍵の追加（root）

```bash
# 1. root権限で admin.html にログイン
# 2. 「信頼済み鍵」タブを開く
# 3. 新しい公開鍵とロールを入力
# 4. 「鍵を追加」をクリック
# 5. Ed25519署名で承認
# 6. 全ノードに自動配布される
```

---

## 16. 将来の拡張候補

- ホールパンチング（ノード間P2P直接接続）
- スマートコントラクト（VM実装）
- モバイルアプリ
- ブロックエクスプローラー（一般向け）
- ライトノード（ブロックヘッダのみ保持）
- 管理パネルのグラフ表示（チャート機能）
- トランザクションフィルタリング機能
- アラート通知システム
