"use strict";
// ============================================================
// BTR - 分散乱数生成
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.RandomManager = void 0;
const crypto_1 = require("crypto");
function sha256(data) {
    return (0, crypto_1.createHash)('sha256').update(data).digest('hex');
}
class RandomManager {
    currentRandom = '';
    commits = new Map();
    reveals = new Map();
    selectedNodes = [];
    phase = 'idle';
    timeoutTimer = null;
    /**
     * 現在の共通乱数を取得
     */
    getCurrentRandom() {
        return this.currentRandom;
    }
    /**
     * 分散乱数生成を開始（1時間ごとに呼ばれる）
     * @returns 選出されたノードIDの配列、またはフォールバック時は空配列
     */
    startRound(activeNodes) {
        this.commits.clear();
        this.reveals.clear();
        this.selectedNodes = [];
        if (activeNodes.length < 3) {
            // フォールバック: シードノードが自分で生成
            this.currentRandom = this.generateFallbackRandom();
            this.phase = 'idle';
            console.log('[Random] ノード不足、フォールバック乱数生成');
            return { selectedNodes: [], fallback: true };
        }
        // ランダムに3ノード選出
        const shuffled = [...activeNodes].sort(() => Math.random() - 0.5);
        this.selectedNodes = shuffled.slice(0, 3).map(n => n.id);
        this.phase = 'commit';
        console.log(`[Random] ラウンド開始、選出: ${this.selectedNodes.join(', ')}`);
        return { selectedNodes: this.selectedNodes, fallback: false };
    }
    /**
     * コミットメント受信
     */
    receiveCommit(nodeId, hash) {
        if (this.phase !== 'commit')
            return false;
        if (!this.selectedNodes.includes(nodeId))
            return false;
        this.commits.set(nodeId, { nodeId, hash });
        console.log(`[Random] コミット受信: ${nodeId} (${this.commits.size}/${this.selectedNodes.length})`);
        // 全員揃ったらRevealフェーズへ
        if (this.commits.size === this.selectedNodes.length) {
            this.phase = 'reveal';
            return true; // 呼び出し側でReveal要求を送信
        }
        return false;
    }
    /**
     * Reveal受信
     */
    receiveReveal(nodeId, value) {
        if (this.phase !== 'reveal')
            return false;
        if (!this.selectedNodes.includes(nodeId))
            return false;
        // コミットと一致するか検証
        const commit = this.commits.get(nodeId);
        if (!commit)
            return false;
        if (sha256(value) !== commit.hash) {
            console.log(`[Random] Reveal不一致: ${nodeId}`);
            return false;
        }
        this.reveals.set(nodeId, { nodeId, value });
        console.log(`[Random] Reveal受信: ${nodeId} (${this.reveals.size}/${this.selectedNodes.length})`);
        // 全員揃ったら乱数合成
        if (this.reveals.size === this.selectedNodes.length) {
            const values = this.selectedNodes.map(id => this.reveals.get(id).value);
            this.currentRandom = sha256(values.join(''));
            this.phase = 'idle';
            console.log(`[Random] 乱数合成完了: ${this.currentRandom.slice(0, 16)}...`);
            return true; // 呼び出し側で結果を配布
        }
        return false;
    }
    /**
     * タイムアウト処理（10秒以内に揃わなかった場合）
     */
    handleTimeout() {
        if (this.phase !== 'idle') {
            console.log(`[Random] タイムアウト（phase: ${this.phase}）、フォールバック`);
            this.currentRandom = this.generateFallbackRandom();
            this.phase = 'idle';
        }
    }
    /**
     * フォールバック乱数生成
     */
    generateFallbackRandom() {
        return sha256((0, crypto_1.randomBytes)(32).toString('hex') + Date.now());
    }
    /**
     * 現在のフェーズ
     */
    getPhase() {
        return this.phase;
    }
    /**
     * 全員コミット済みか
     */
    allCommitted() {
        return this.commits.size === this.selectedNodes.length;
    }
    /**
     * 全員Reveal済みか
     */
    allRevealed() {
        return this.reveals.size === this.selectedNodes.length;
    }
}
exports.RandomManager = RandomManager;
//# sourceMappingURL=random.js.map