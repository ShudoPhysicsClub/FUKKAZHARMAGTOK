# BTR (Buturi Coin) ブロックチェーン 設計仕様書

## 概要
物理部（修道中学校）の文化祭向け独自ブロックチェーン。
ネイティブコイン BTR (Buturi Coin) と、ユーザーが自由に作成できるトークンシステムを持つ。

---

## ネットワーク構成

### シードノード
- ホスト: `shudo-physics.f5.si`
- 役割:
  - ノード発見（新ノードにノードリストを教える）
  - ノード間通信の中継（TCP）
  - クライアント接続の受付（WSS :443）→ フルノードにTCP中継
  - 分散乱数生成の合図
- チェーンデータは持たない（軽量）
- SSL証明書はシードノードだけ持つ（Let's Encrypt）

### フルノード（ラズパイたち）
- ラズパイ4B、zero2w、（将来）ラズパイ5
- 役割:
  - ブロックチェーンデータの保存
  - トランザクション検証
  - ブロック検証
  - クライアントへのAPI提供（TCP経由、シードノードが中継）
- ポート開放不要（シードノードにアウトバウンド接続するだけ）
- マイニングはしない

### クライアント（ブラウザ）
- WSS経由でシードノードに接続 → シードノードがフルノードに中継
- 役割:
  - ウォレット管理（鍵ペア生成、秘密鍵保管）
  - 送金・トークン操作
  - マイニング（WebWorkerでPoW計算）
  - ブロック情報閲覧

### 通信プロトコル
- ノード間: TCP（シードノード中継、将来的にホールパンチングでP2P直接接続）
- クライアント → シードノード: WSS (WebSocket Secure)
- シードノード → フルノード: TCP

### ノード発見
1. シードノードに接続 → ノードリスト取得
2. 失敗時: ローカルキャッシュから前回のピアに接続
3. 最終手段: ローカルネットワークでマルチキャスト探索

### 接続管理
- 全ノードがシードノードと常時TCP接続
- 切断検出: TCP close イベント + ハートビート（定期生存確認）
- 切断時: 自動再接続
- ノードリストからの自動削除・通知

---

## 権限システム

### ロール
- **root**: 全権限（マインのみ、追加はrootだけ可能）
- **member**: メンバー追加 + アップデート配信

### 権限表
| 操作 | root | member |
|------|------|--------|
| メンバー追加 | ✅ | ✅ |
| root追加 | ✅ | ❌ |
| メンバー削除 | ✅ | ❌ |
| アップデート配信 | ✅ | ✅ |

### 信頼チェーン
- マインのEd25519公開鍵をシードノードとジェネシスブロックに埋め込み（信頼の起点）
- メンバー追加時: 追加者がEd25519で新メンバーの公開鍵に署名
- 検証: ジェネシスブロックのroot公開鍵から信頼チェーンを辿る

---

## アップデートシステム

### ランチャー方式
```typescript
// launcher.ts（更新不要、シンプル）
import { fork } from 'child_process';

function startNode() {
  const node = fork('./node.js');
  node.on('exit', (code) => {
    if (code === 100) {
      // アップデート適用後の再起動
      startNode();
    } else {
      // クラッシュ時も再起動（3秒待ち）
      setTimeout(startNode, 3000);
    }
  });
}
startNode();
```

### アップデート配信フロー
1. root/memberが新コードを作成
2. sha256(パッケージ)を計算
3. 秘密鍵で署名
4. シードノードに送信
5. シードノード → 全ノードに通知
6. 各ノード: 署名検証 → ハッシュ検証 → ファイル上書き → process.exit(100)
7. ランチャーが新コードで再起動

---

## コイン: BTR (Buturi Coin)

### パラメータ
- 名前: Buturi Coin
- シンボル: BTR
- トークンアドレス: `0x0000000000000000`
- 総供給量: 50億 BTR
- ブロック時間: 45秒
- ブロック報酬: 80〜120 BTR（分散乱数で決定、平均100）
- 1日あたり: 約192,000 BTR（1920ブロック × 平均100）
- 枯渇まで: 約68年
- ガス代: 0.5 BTR
- トークン作成費: 10,000 BTR
- トークン名変更費: 500 BTR
- 手数料の行き先: 全てマイナー（ブロック生成者）へ

---

## トークンシステム

### トークン作成
- 費用: 10,000 BTR（マイナーの報酬に入る）
- トークンアドレス: 64bit乱数 (`crypto.randomBytes(8)`)
- 配布方式（選択可能）:
  - `creator`: 全額作成者に渡る
  - `mining`: BTRマイニングと一緒に徐々に発行
  - `split`: 指定比率で作成者とプールに分配
  - `airdrop`: 接続中のウォレットに均等配布

### トークンメタデータ
```typescript
interface TokenInfo {
  address: string;        // 0x + 16文字（64bit乱数）
  symbol: string;         // PHY
  name: string;           // PhysicsCoin
  creator: string;        // 作成者の公開鍵
  createdAt: number;      // 作成日時
  totalSupply: number;    // 総発行量
  poolRatio: number;      // プールに入れる比率
  distribution: string;   // 配布方式
}
```

### 初期流動性
- トークン作成費の10,000 BTRがそのままAMMプールに入る
- 初期レート = (totalSupply × poolRatio) / 10000
- 作成者には totalSupply × (1 - poolRatio) が渡る
- プールはロック（引き出し不可）

---

## AMM (自動マーケットメイカー)

### 基本設計
- 全トークンはBTR建て（BTRが基軸通貨）
- トークン同士の交換はBTR経由で計算
- レート = 需要供給（AMM）+ 分散乱数による揺らぎ（±15%）
- レート変動: 1分ごと

### レート計算
```typescript
function getRate(commonRandom: string, token: string, minute: number): number {
  // AMMプールからベースレート
  const base = getAMMRate('BTR', token);
  
  // 共通乱数 + 分で1分ごとに違う揺らぎ
  const seed = sha256(commonRandom + token + minute);
  const fluctuation = parseInt(seed.slice(0, 8), 16);
  
  // ±15%の範囲
  const change = (fluctuation % 3000 - 1500) / 10000;
  
  return base * (1 + change);
}
```

### トークン間交換
```typescript
function getCrossRate(tokenA: string, tokenB: string): number {
  return rates.get(tokenB) / rates.get(tokenA);
}
```

---

## 分散乱数生成

### フロー
1. 1時間ごとにシードサーバーが合図を送る
2. シードサーバーがランダムに3ノードを選出
3. 選出されたノードがコミットメント（hash(乱数)）を提出
4. 全員出揃ったら乱数を公開
5. シードサーバーが合体: `sha256(randomA + randomB + randomC)`
6. 共通乱数を全ノードに配布

### 用途
- BTRブロック報酬（80〜120）の決定
- 各トークンのブロック報酬の決定
- AMMレートの揺らぎ
- コインごとに異なる値を導出: `sha256(commonRandom + tokenSymbol + purpose)`

---

## 暗号技術

### 署名
- Ed25519（自作実装）
- ウォレットの鍵ペア生成
- トランザクション署名・検証
- アップデート署名

### ハッシュ
- SHA-256
- ブロックハッシュ
- PoWのnonce探索
- アドレス生成
- 分散乱数

### ウォレットアドレス
- Ed25519公開鍵からSHA-256ハッシュ → 先頭160bit（40文字）
- 形式: `0x` + 40文字（Ethereumと同じ長さ）
- トークンアドレス（16文字）と長さで区別可能

```typescript
function createWallet() {
  const { publicKey, privateKey } = ed25519.generateKeyPair();
  const address = '0x' + sha256(publicKey).slice(0, 40);
  return { publicKey, privateKey, address };
}
```

---

## ブロック構造

```typescript
interface Block {
  // ヘッダー
  height: number;              // ブロック番号
  previousHash: string;        // 前ブロックのハッシュ
  timestamp: number;           // 生成時刻
  nonce: number;               // PoW用
  difficulty: number;          // 難易度
  
  // 中身
  miner: string;               // マイナーのアドレス
  reward: number;              // このブロックの報酬（80-120 BTR）
  transactions: Transaction[];
  
  // ハッシュ
  hash: string;                // このブロックのSHA-256ハッシュ
}
```

---

## トランザクション構造

```typescript
interface Transaction {
  type: 'transfer' | 'create_token' | 'token_transfer' | 'swap' | 'rename_token';
  token: string;          // 対象トークンアドレス（BTR: '0x0000000000000000'）
  from: string;           // 送信者アドレス
  publicKey: string;      // 送信者のEd25519公開鍵（署名検証用）
  to?: string;            // 受信者アドレス
  amount?: number;        // 送金額
  fee: number;            // ガス代（BTR建て）
  timestamp: number;      // クライアントの時刻
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

### 署名対象
- signature以外の全フィールドをJSON化して署名

### 検証
1. `sha256(publicKey).slice(0, 40) === from` か確認
2. Ed25519で署名を検証
3. タイムスタンプが±10分以内か確認

---

## PoW (Proof of Work)

### マイニング
- クライアント（ブラウザ）がWebWorkerでSHA-256を計算
- ハッシュの先頭が難易度に応じた数の0で始まるnonceを探す

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

### 難易度調整
- 目標: 45秒/ブロック
- 直近10ブロックの平均生成時間で調整
- 40秒未満 → 難易度+1
- 50秒超過 → 難易度-1（最低1）
- マイナー0人 → ブロック生成停止、次のマイナーが来たら再開

---

## ジェネシスブロック

```typescript
const genesisBlock: Block = {
  height: 0,
  previousHash: '0x' + '0'.repeat(64),
  timestamp: チェーン起動日時,
  nonce: 0,
  difficulty: 1,
  miner: '0x' + '0'.repeat(40),
  reward: 0,
  transactions: [],
  hash: 計算値,

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
    timestampTolerance: 600000, // ±10分
    admin: {
      publicKey: 'マインのEd25519公開鍵',
      address: 'マインのウォレットアドレス',
    }
  },

  message: 'Foooooooooooooooooooo物理班最高!YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA',
};
```

---

## アドレス体系まとめ

| 種類 | 長さ | 形式 | 例 |
|------|------|------|-----|
| ウォレットアドレス | 160bit (40文字) | `0x` + sha256(公開鍵)[:40] | `0xa3f1b2c4d5e6f7089b1c2d3e4f5a6b7c8d9e0f12` |
| トークンアドレス | 64bit (16文字) | `0x` + randomBytes(8) | `0x7a2b9c4d1e5f8a03` |
| BTRアドレス | 64bit (16文字) | 固定 | `0x0000000000000000` |

---

## 今後の拡張候補
- ホールパンチング（ノード間P2P直接接続）
- シードノード複数化
- スマートコントラクト（VM実装）
- モバイルアプリ
