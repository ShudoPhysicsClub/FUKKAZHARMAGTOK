import { Packet } from './types';
import net from 'net';
import { WebSocket } from 'ws';
/**
 * Canonical JSON: キーをアルファベット順にソートして決定論的なJSON文字列を生成
 */
export declare function canonicalJSON(obj: any): string;
/**
 * パケットをJSON + DELIMITER形式にシリアライズ
 */
export declare function serializePacket(packet: Packet): string;
/**
 * TCP/WSSのバッファからパケットを分割して取り出す
 */
export declare class PacketBuffer {
    private buffer;
    /**
     * データを追加してパースされたパケットを返す
     */
    feed(data: string): Packet[];
    /**
     * バッファをクリア
     */
    clear(): void;
}
/**
 * TCPソケットにパケットを送信
 */
export declare function sendTCP(socket: net.Socket, packet: Packet): void;
/**
 * WebSocketにパケットを送信
 */
export declare function sendWS(ws: WebSocket, packet: Packet): void;
