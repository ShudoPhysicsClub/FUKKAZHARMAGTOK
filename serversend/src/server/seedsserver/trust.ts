// ============================================================
// BTR - 信頼管理（権限・鍵管理）
// crypto.ts の Ed25519 を使用
// ============================================================

import { TrustedKey, TrustedKeysFile, Role, UpdatePackage } from './types';
import { canonicalJSON } from './protocol';
import { Ed25519 } from './crypto';
import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';

// ============================================================
// ヘルパー: hex文字列 ↔ Uint8Array 変換
// ============================================================

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

// ============================================================

const TRUSTED_KEYS_PATH = path.resolve('./trusted_keys.json');

export class TrustManager {
  private rootKey: string;  // hex文字列（64文字 = 32バイト公開鍵）
  private trustedKeys: Map<string, TrustedKey> = new Map();

  constructor(rootPublicKey: string) {
    this.rootKey = rootPublicKey;
    this.loadTrustedKeys();
  }

  // --- ファイル管理 ---

  private loadTrustedKeys(): void {
    try {
      if (fs.existsSync(TRUSTED_KEYS_PATH)) {
        const data: TrustedKeysFile = JSON.parse(fs.readFileSync(TRUSTED_KEYS_PATH, 'utf-8'));
        for (const key of data.keys) {
          this.trustedKeys.set(key.publicKey, key);
        }
        console.log(`[Trust] ${this.trustedKeys.size}件の信頼済み鍵をロード`);
      } else {
        const empty: TrustedKeysFile = { keys: [] };
        fs.writeFileSync(TRUSTED_KEYS_PATH, JSON.stringify(empty, null, 2));
        console.log('[Trust] trusted_keys.json を新規作成');
      }
    } catch (e) {
      console.error('[Trust] trusted_keys.json ロード失敗:', e);
    }
  }

  private saveTrustedKeys(): void {
    const data: TrustedKeysFile = {
      keys: Array.from(this.trustedKeys.values())
    };
    fs.writeFileSync(TRUSTED_KEYS_PATH, JSON.stringify(data, null, 2));
  }

  syncTrustedKeys(data: TrustedKeysFile): void {
    this.trustedKeys.clear();
    for (const key of data.keys) {
      this.trustedKeys.set(key.publicKey, key);
    }
    this.saveTrustedKeys();
    console.log(`[Trust] 同期完了: ${this.trustedKeys.size}件`);
  }

  getTrustedKeysFile(): TrustedKeysFile {
    return {
      keys: Array.from(this.trustedKeys.values())
    };
  }

  // --- 信頼チェック ---

  isTrusted(publicKey: string): boolean {
    return publicKey === this.rootKey || this.trustedKeys.has(publicKey);
  }

  getRole(publicKey: string): Role | null {
    if (publicKey === this.rootKey) return 'root';
    const key = this.trustedKeys.get(publicKey);
    return key ? key.role : null;
  }

  isRoot(publicKey: string): boolean {
    return this.getRole(publicKey) === 'root';
  }

  // --- 権限チェック ---

  canAddMember(publicKey: string): boolean {
    return this.isTrusted(publicKey);
  }

  canAddRoot(publicKey: string): boolean {
    return this.isRoot(publicKey);
  }

  canRemoveMember(publicKey: string): boolean {
    return this.isRoot(publicKey);
  }

  canUpdate(publicKey: string): boolean {
    return this.isTrusted(publicKey);
  }

  canUpdateSeeds(publicKey: string): boolean {
    return this.isRoot(publicKey);
  }

  // --- Ed25519 署名検証ラッパー ---

  /**
   * Ed25519署名検証
   * @param message - 署名対象の文字列
   * @param signature - 署名（hex文字列, 128文字 = 64バイト）
   * @param publicKey - 公開鍵（hex文字列, 64文字 = 32バイト）
   */
  private async ed25519Verify(message: string, signature: string, publicKey: string): Promise<boolean> {
    try {
      const sigBytes = hexToBytes(signature);
      const msgBytes = stringToBytes(message);
      const pubBytes = hexToBytes(publicKey);
      return await Ed25519.verify(sigBytes, msgBytes, pubBytes);
    } catch (e) {
      console.error('[Trust] Ed25519 verify エラー:', e);
      return false;
    }
  }

  // --- メンバー管理 ---

  async addMember(newPublicKey: string, role: Role, addedBy: string, signature: string): Promise<boolean> {
    if (role === 'root' && !this.canAddRoot(addedBy)) {
      console.log('[Trust] root追加はrootのみ可能');
      return false;
    }
    if (!this.canAddMember(addedBy)) {
      console.log('[Trust] 信頼されていない鍵からのメンバー追加');
      return false;
    }

    // 署名検証: sign(newPublicKey + role, addedByの秘密鍵)
    const message = newPublicKey + role;
    if (!await this.ed25519Verify(message, signature, addedBy)) {
      console.log('[Trust] 署名検証失敗');
      return false;
    }

    const trustedKey: TrustedKey = {
      publicKey: newPublicKey,
      role,
      addedBy,
      signature
    };

    this.trustedKeys.set(newPublicKey, trustedKey);
    this.saveTrustedKeys();
    console.log(`[Trust] メンバー追加: ${newPublicKey.slice(0, 16)}... (${role})`);
    return true;
  }

  removeMember(publicKey: string, removedBy: string): boolean {
    if (!this.canRemoveMember(removedBy)) {
      console.log('[Trust] メンバー削除はrootのみ可能');
      return false;
    }
    if (publicKey === this.rootKey) {
      console.log('[Trust] rootは削除できません');
      return false;
    }

    this.trustedKeys.delete(publicKey);
    this.saveTrustedKeys();
    console.log(`[Trust] メンバー削除: ${publicKey.slice(0, 16)}...`);
    return true;
  }

  // --- アップデート検証 ---

  async verifyUpdate(update: UpdatePackage): Promise<boolean> {
    // 1. 署名者が信頼されているか
    if (!this.canUpdate(update.signer)) {
      console.log('[Trust] アップデート: 署名者が信頼されていません');
      return false;
    }

    // 2. ハッシュが合っているか
    if (sha256(update.code) !== update.hash) {
      console.log('[Trust] アップデート: ハッシュ不一致');
      return false;
    }

    // 3. 署名が正しいか
    if (!await this.ed25519Verify(update.hash, update.signature, update.signer)) {
      console.log('[Trust] アップデート: 署名検証失敗');
      return false;
    }

    return true;
  }

  // --- seeds.json 検証 ---

  async verifySeedsJson(seedsData: any): Promise<boolean> {
    const { signature, ...rest } = seedsData;
    return await this.ed25519Verify(canonicalJSON(rest), signature, this.rootKey);
  }

  getRootKey(): string {
    return this.rootKey;
  }
}