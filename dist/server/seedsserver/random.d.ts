import { NodeInfo } from './types';
export declare class RandomManager {
    private currentRandom;
    private commits;
    private reveals;
    private selectedNodes;
    private phase;
    private timeoutTimer;
    /**
     * 現在の共通乱数を取得
     */
    getCurrentRandom(): string;
    /**
     * 分散乱数生成を開始（1時間ごとに呼ばれる）
     * @returns 選出されたノードIDの配列、またはフォールバック時は空配列
     */
    startRound(activeNodes: NodeInfo[]): {
        selectedNodes: string[];
        fallback: boolean;
    };
    /**
     * コミットメント受信
     */
    receiveCommit(nodeId: string, hash: string): boolean;
    /**
     * Reveal受信
     */
    receiveReveal(nodeId: string, value: string): boolean;
    /**
     * タイムアウト処理（10秒以内に揃わなかった場合）
     */
    handleTimeout(): void;
    /**
     * フォールバック乱数生成
     */
    private generateFallbackRandom;
    /**
     * 現在のフェーズ
     */
    getPhase(): string;
    /**
     * 全員コミット済みか
     */
    allCommitted(): boolean;
    /**
     * 全員Reveal済みか
     */
    allRevealed(): boolean;
}
