"use strict";
// ============================================================
// BTR - 信頼管理（権限・鍵管理）
// crypto.ts の Ed25519 を使用
// ============================================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrustManager = void 0;
const protocol_1 = require("./protocol");
const crypto_1 = require("./crypto");
const crypto_2 = require("crypto");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
// ============================================================
// ヘルパー: hex文字列 ↔ Uint8Array 変換
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
function stringToBytes(str) {
    return new TextEncoder().encode(str);
}
function sha256(data) {
    return (0, crypto_2.createHash)('sha256').update(data).digest('hex');
}
// ============================================================
const TRUSTED_KEYS_PATH = path_1.default.resolve('./trusted_keys.json');
class TrustManager {
    rootKey; // hex文字列（64文字 = 32バイト公開鍵）
    trustedKeys = new Map();
    constructor(rootPublicKey) {
        this.rootKey = rootPublicKey;
        this.loadTrustedKeys();
    }
    // --- ファイル管理 ---
    loadTrustedKeys() {
        try {
            if (fs_1.default.existsSync(TRUSTED_KEYS_PATH)) {
                const data = JSON.parse(fs_1.default.readFileSync(TRUSTED_KEYS_PATH, 'utf-8'));
                for (const key of data.keys) {
                    this.trustedKeys.set(key.publicKey, key);
                }
                console.log(`[Trust] ${this.trustedKeys.size}件の信頼済み鍵をロード`);
            }
            else {
                const empty = { keys: [] };
                fs_1.default.writeFileSync(TRUSTED_KEYS_PATH, JSON.stringify(empty, null, 2));
                console.log('[Trust] trusted_keys.json を新規作成');
            }
        }
        catch (e) {
            console.error('[Trust] trusted_keys.json ロード失敗:', e);
        }
    }
    saveTrustedKeys() {
        const data = {
            keys: Array.from(this.trustedKeys.values())
        };
        fs_1.default.writeFileSync(TRUSTED_KEYS_PATH, JSON.stringify(data, null, 2));
    }
    syncTrustedKeys(data) {
        this.trustedKeys.clear();
        for (const key of data.keys) {
            this.trustedKeys.set(key.publicKey, key);
        }
        this.saveTrustedKeys();
        console.log(`[Trust] 同期完了: ${this.trustedKeys.size}件`);
    }
    getTrustedKeysFile() {
        return {
            keys: Array.from(this.trustedKeys.values())
        };
    }
    // --- 信頼チェック ---
    isTrusted(publicKey) {
        return publicKey === this.rootKey || this.trustedKeys.has(publicKey);
    }
    getRole(publicKey) {
        if (publicKey === this.rootKey)
            return 'root';
        const key = this.trustedKeys.get(publicKey);
        return key ? key.role : null;
    }
    isRoot(publicKey) {
        return this.getRole(publicKey) === 'root';
    }
    // --- 権限チェック ---
    canAddMember(publicKey) {
        return this.isTrusted(publicKey);
    }
    canAddRoot(publicKey) {
        return this.isRoot(publicKey);
    }
    canRemoveMember(publicKey) {
        return this.isRoot(publicKey);
    }
    canUpdate(publicKey) {
        return this.isTrusted(publicKey);
    }
    canUpdateSeeds(publicKey) {
        return this.isRoot(publicKey);
    }
    // --- Ed25519 署名検証ラッパー ---
    /**
     * Ed25519署名検証
     * @param message - 署名対象の文字列
     * @param signature - 署名（hex文字列, 128文字 = 64バイト）
     * @param publicKey - 公開鍵（hex文字列, 64文字 = 32バイト）
     */
    async ed25519Verify(message, signature, publicKey) {
        try {
            const sigBytes = hexToBytes(signature);
            const msgBytes = stringToBytes(message);
            const pubBytes = hexToBytes(publicKey);
            return await crypto_1.Ed25519.verify(sigBytes, msgBytes, pubBytes);
        }
        catch (e) {
            console.error('[Trust] Ed25519 verify エラー:', e);
            return false;
        }
    }
    // --- メンバー管理 ---
    async addMember(newPublicKey, role, addedBy, signature) {
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
        const trustedKey = {
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
    removeMember(publicKey, removedBy) {
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
    async verifyUpdate(update) {
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
    async verifySeedsJson(seedsData) {
        const { signature, ...rest } = seedsData;
        return await this.ed25519Verify((0, protocol_1.canonicalJSON)(rest), signature, this.rootKey);
    }
    getRootKey() {
        return this.rootKey;
    }
}
exports.TrustManager = TrustManager;
//# sourceMappingURL=trust.js.map