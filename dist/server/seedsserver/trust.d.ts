import { TrustedKeysFile, Role, UpdatePackage } from './types.js';
export declare class TrustManager {
    private rootKey;
    private trustedKeys;
    constructor(rootPublicKey: string);
    private loadTrustedKeys;
    private saveTrustedKeys;
    syncTrustedKeys(data: TrustedKeysFile): void;
    getTrustedKeysFile(): TrustedKeysFile;
    isTrusted(publicKey: string): boolean;
    getRole(publicKey: string): Role | null;
    isRoot(publicKey: string): boolean;
    canAddMember(publicKey: string): boolean;
    canAddRoot(publicKey: string): boolean;
    canRemoveMember(publicKey: string): boolean;
    canUpdate(publicKey: string): boolean;
    canUpdateSeeds(publicKey: string): boolean;
    /**
     * Ed25519署名検証
     * @param message - 署名対象の文字列
     * @param signature - 署名（hex文字列, 128文字 = 64バイト）
     * @param publicKey - 公開鍵（hex文字列, 64文字 = 32バイト）
     */
    private ed25519Verify;
    addMember(newPublicKey: string, role: Role, addedBy: string, signature: string): Promise<boolean>;
    removeMember(publicKey: string, removedBy: string): boolean;
    verifyUpdate(update: UpdatePackage): Promise<boolean>;
    verifySeedsJson(seedsData: any): Promise<boolean>;
    getRootKey(): string;
}
