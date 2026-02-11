// ============================================================
// BTR - パケット送受信プロトコル
// ============================================================

import { DELIMITER, Packet } from './types';
import net from 'net';
import { WebSocket } from 'ws';

/**
 * Canonical JSON: キーをアルファベット順にソートして決定論的なJSON文字列を生成
 */
export function canonicalJSON(obj: any): string {
  if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';

  const keys = Object.keys(obj).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`);
  return '{' + pairs.join(',') + '}';
}

/**
 * パケットをJSON + DELIMITER形式にシリアライズ
 */
export function serializePacket(packet: Packet): string {
  return JSON.stringify(packet) + DELIMITER;
}

/**
 * TCP/WSSのバッファからパケットを分割して取り出す
 */
export class PacketBuffer {
  private buffer: string = '';

  /**
   * データを追加してパースされたパケットを返す
   */
  feed(data: string): Packet[] {
    this.buffer += data;
    const parts = this.buffer.split(DELIMITER);
    this.buffer = parts.pop() || '';

    const packets: Packet[] = [];
    for (const part of parts) {
      if (part.trim()) {
        try {
          packets.push(JSON.parse(part));
        } catch (e) {
          console.error('[Protocol] JSON parse error:', e);
        }
      }
    }
    return packets;
  }

  /**
   * バッファをクリア
   */
  clear(): void {
    this.buffer = '';
  }
}

/**
 * TCPソケットにパケットを送信
 */
export function sendTCP(socket: net.Socket, packet: Packet): void {
  socket.write(serializePacket(packet));
}

/**
 * WebSocketにパケットを送信
 */
export function sendWS(ws: WebSocket, packet: Packet): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(serializePacket(packet));
  }
}
