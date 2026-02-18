# BTR (Buturi Coin) ブロックチェーン 最終設計仕様書
**v3.0 — BigInt + LWMA Edition**

---

## 1. 概要

独自ブロックチェーン。ネイティブコイン **BTR (Buturi Coin)** と、ユーザーが自由に作成できるトークンシステム、組み込み型AMM（自動マーケットメイカー）を持つ。将来の実用化も視野に入れた設計。

全金額はWei文字列で管理する（1 BTR = 10^18 wei）。

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

### 2.2 フルノード（Raspberry Pi）

- 機種: Raspberry Pi 4B、Zero 2W、（将来）Pi 5
- 役割:
  - ブロックチェーンデータの保存
  - トランザクション検証
  - ブロック検証
  - アカウント状態管理
- ポート開放不要（シードノードにアウトバウンド接続するだけ）
- マイニングはしない

### 2.3 クライアント（ブラウザ）

- WSS経由でシードノードに接続 → シードノードがフルノードに中継
- 役割:
  - ウォレット管理（鍵ペア生成、秘密鍵保管）
  - 送金・トークン操作・スワップ
  - マイニング（Web WorkerでPoW計算）
  - ブロック情報閲覧

### 2.4 通信プロトコル

| 経路 | プロトコル |
|------|-----------|
| クライアント → シードノード | WSS (WebSocket Secure) |
| シードノード → フルノード | TCP |
| シードノード ↔ シードノード | TCP（常時接続） |

### 2.5 パケットフォーマット

JSON + 改行 + `LINE_BREAK` + 改行 を区切り文字として使用。

```typescript
const DELIMITER = '\nLINE_BREAK\n';

socket.write(JSON.stringify(packet) + DELIMITER);
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
address = '0x' + sha256(publicKey).slice(0, 40)
```

### 3.4 アドレス体系

| 種類 | 長さ | 形式 |
|------|------|------|
| ウォレットアドレス | 160bit (42文字) | `0x` + sha256(公開鍵)[:40] |
| トークンアドレス | 64bit (18文字) | `0x` + sha256(sig+timestamp)[:16] |
| BTRアドレス | 64bit (18文字) | 固定: `0x0000000000000000` |

### 3.5 Canonical JSON

署名・検証時にキーをアルファベット順ソートして決定論的なJSON文字列を生成。

```typescript
function canonicalJSON(obj: any): string {
  if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`).join(',') + '}';
}
```

---

## 4. アカウントシステム

アカウントは使われた時に初めて作成される（遅延初期化）。

### 4.1 Nonce（リプレイ攻撃対策）

Ethereum方式のアカウントnonceカウンター。pendingトランザクションを考慮した実効nonceをクライアントに返す。

| フィールド | 説明 |
|-----------|------|
| `nonce` | 確定済みnonce（ブロックに含まれたTx数） |
| `pendingNonce` | pending考慮後の次のnonce（クライアントが使う値） |

---

## 5. トランザクション

### 5.1 種別

| type | 説明 |
|------|------|
| `transfer` | BTR送金 |
| `token_transfer` | トークン送金 |
| `create_token` | トークン作成 |
| `swap` | AMMスワップ |
| `rename_token` | トークン名変更 |

### 5.2 検証フロー

1. 公開鍵 → アドレス整合性チェック
2. Ed25519署名検証
3. タイムスタンプ ±10分チェック
4. nonce検証（pending考慮の実効nonce）
5. ガス代チェック（固定 1 BTR）
6. pending考慮の実効残高チェック
7. type別チェック（残高、プール存在など）

### 5.3 署名

`signature` フィールドを除いた全フィールドをCanonical JSON化して署名。

---

## 6. ブロック

### 6.1 ブロックハッシュ計算

```typescript
sha256(previousHash + timestamp + nonce + difficulty + miner + reward + JSON.stringify(transactions))
```

### 6.2 ブロックサイズ上限

3MB（約6000トランザクション/ブロック）

### 6.3 フォーク選択ルール

累積ワーク量（Σ 2^difficulty）が大きい方が正。同じ場合はチェーン長が長い方。最大巻き戻し深さ: 10ブロック。

```typescript
function calculateChainWork(c: Block[]): bigint {
  return c.reduce((sum, b) => sum + (2n ** BigInt(b.difficulty)), 0n);
}
```

---

## 7. Proof of Work

### 7.1 マイニング

クライアント（ブラウザ）がWeb WorkerでSHA-256を計算。難易度はビット単位（先頭Nビットが0）。

```typescript
function meetsTarget(hash: string, difficulty: number): boolean {
  const fullNibbles = Math.floor(difficulty / 4);
  const remainBits = difficulty % 4;
  for (let i = 0; i < fullNibbles; i++) {
    if (hash[i] !== '0') return false;
  }
  if (remainBits > 0) {
    const v = parseInt(hash[fullNibbles], 16);
    if (v > (1 << (4 - remainBits)) - 1) return false;
  }
  return true;
}
```

### 7.2 難易度調整（LWMA）

線形加重移動平均（Linear Weighted Moving Average）方式。直近ほど重みが大きい。

| パラメータ | 値 |
|-----------|-----|
| 目標ブロック時間 | **180秒** |
| 調整ウィンドウ | **20ブロック** |
| 調整開始 | 20ブロック以降 |
| 初期難易度 | 24ビット |
| 最低難易度 | 20ビット |
| 外れ値フィルタ | 30秒〜900秒（クランプ） |
| ダンピング係数 | 1/3（変化量を抑制） |
| 最大上昇幅 | +1/ブロック |

---

## 8. コイン: BTR (Buturi Coin)

### 8.1 パラメータ

| パラメータ | 値 |
|-----------|-----|
| 名前 | Buturi Coin |
| シンボル | BTR |
| トークンアドレス | `0x0000000000000000` |
| 総供給量 | 50億 BTR |
| 単位 | Wei（1 BTR = 10^18 wei） |
| ブロック時間（目標） | **180秒（約3分）** |
| ブロック報酬 | **20〜70 BTR**（前ブロックハッシュベースで決定論的に算出） |
| ガス代 | **1 BTR**（固定） |
| トークン作成費 | **500 BTR** |
| トークン名変更費 | **500 BTR** |
| 手数料の行き先 | 全てマイナー（ブロック生成者）へ |

### 8.2 ブロック報酬算出

前ブロックハッシュ + `'BTR_REWARD'` + height をSHA-256して決定論的に算出。

```typescript
const seed = sha256(prevHash + 'BTR_REWARD' + height);
const rewardBtr = 20 + (parseInt(seed.slice(0, 8), 16) % 51); // 20〜70
const rewardWei = (BigInt(rewardBtr) * WEI_PER_BTR).toString();
```

### 8.3 初期配布

事前配布なし。最初のマイナーが最初のブロックを掘ることでBTR経済圏がスタート。

---

## 9. トークンシステム

### 9.1 トークン作成

- 費用: **500 BTR**（マイナーの報酬として入る）
- トークンアドレス: `sha256(署名 + タイムスタンプ)` の先頭16文字

### 9.2 配布方式

| 方式 | 説明 |
|------|------|
| `creator` | 全額作成者に渡る |
| `mining` | BTRマイニングと一緒に徐々に発行（100トークン/ブロック） |
| `amm` | 全量AMMプールに投入（クライアントデフォルト） |
| `split` | 指定比率（poolRatio: 0〜1）で作成者とプールに分配 |
| `airdrop` | 接続中のウォレットに均等配布 |

### 9.3 初期流動性

- トークン作成費の500 BTRがAMMプールの初期BTRリザーブになる
- `totalSupply × poolRatio` のトークンがプールに入る
- `totalSupply × (1 - poolRatio)` が作成者に渡る
- プールはロック（引き出し不可）

---

## 10. AMM（自動マーケットメイカー）

### 10.1 基本設計

- 全トークンはBTR建て（BTRが基軸通貨）
- トークン同士の交換: TokenA → BTR → TokenB（二重手数料）
- 手数料: **3%**
- 定数積モデル（x × y = k）

### 10.2 レート計算

```typescript
// 基本レート（手数料込み）
rate = btrReserve * 97n * WEI_PER_BTR / (tokenReserve * 100n)

// 揺らぎ（±15%、1分ごとに変化）
const seed = sha256(lastBlockHash + tokenAddress + minute);
const change = parseInt(seed.slice(0, 8), 16) % 3000 - 1500; // -1500〜+1500
```

### 10.3 スワップ計算

```typescript
// 定数積AMM（手数料3%）
const fee = amountIn * 3n / 100n;
const amountInAfterFee = amountIn - fee;
const amountOut = amountInAfterFee * reserve_out / (reserve_in + amountInAfterFee);
```

---

## 11. 分散乱数生成

### 11.1 通常フロー（1時間ごと）

1. プライマリシードノードが合図を送る
2. ランダムに3ノードを選出
3. 選出されたノードがコミットメント `hash(乱数)` を提出
4. 全員出揃ったら乱数を公開（Reveal）
5. `sha256(randomA + randomB + randomC)` を共通乱数として全体に配布

### 11.2 フォールバック

ノードが3台未満またはタイムアウト（10秒）時: シードノードが自分で乱数を生成して配布。

---

## 12. 権限システム

### 12.1 ロール

| ロール | 説明 |
|--------|------|
| root | 全権限（seeds.json更新を含む） |
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
- `trusted_keys.json` でメンバー公開鍵を管理
- シードノード間で常時同期

---

## 13. アップデートシステム

### 13.1 ランチャー方式

- `launcher.ts` が署名検証とプロセス管理を担当
- ランチャー自体は更新しない（root公開鍵とCDN URLをハードコード）
- `exit(1)` → ランチャーが再起動
- `exit(100)` → アップデート適用後の再起動

### 13.2 アップデートパッケージ

| フィールド | 内容 |
|-----------|------|
| `version` | バージョン文字列 |
| `code` | ノードコード全体（ミニファイ済み1行） |
| `hash` | sha256(code) |
| `signer` | 署名者の公開鍵 |
| `signature` | Ed25519署名 |

---

## 14. チェーン同期

### 14.1 フロー

接続（または再接続）のたびに差分同期を実施。

1. シードノードに接続 → `register` 送信
2. シードノードが `send_chain_to` で既存ノードに送信指示
3. 50ブロック単位のチャンクでストリーミング受信
4. チャンクをディスク（`sync_chain/`）に即書き出し
5. 全チャンク到着後 `applySyncedChain()` でrebuild

### 14.2 検証

- 末尾 10ブロックのPoW・ハッシュチェーン検証
- フォーク選択は累積ワーク量比較
- 最大巻き戻し深さ: 10ブロック

---

## 15. ジェネシスブロック

タイムスタンプ固定: `1739700000000`（2025-02-16T00:00:00Z）  
全ノードで同一のジェネシスハッシュを保証するため固定値を使用。

| フィールド | 値 |
|-----------|-----|
| height | 0 |
| previousHash | `0x` + `0` × 64 |
| timestamp | `1739700000000`（固定） |
| nonce | 0 |
| difficulty | 24 |
| miner | `0x` + `0` × 40 |
| reward | 0 |
| message | `Foooooooooooooooooooo物理班最高!YEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA BigInt+LWMA Edition v2.1.0` |

---

## 16. 将来の拡張候補

- ホールパンチング（ノード間P2P直接接続）
- スマートコントラクト（VM実装）
- モバイルアプリ
- ブロックエクスプローラー（一般向け）
- ライトノード（ブロックヘッダのみ保持）
- 並列チェーン同期（複数ノードから分担取得）
- 管理パネルのグラフ表示
- トランザクションフィルタリング機能
- アラート通知システム