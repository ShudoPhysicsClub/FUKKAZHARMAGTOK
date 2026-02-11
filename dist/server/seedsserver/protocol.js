"use strict";
// ============================================================
// BTR - パケット送受信プロトコル
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.PacketBuffer = void 0;
exports.canonicalJSON = canonicalJSON;
exports.serializePacket = serializePacket;
exports.sendTCP = sendTCP;
exports.sendWS = sendWS;
const types_1 = require("./types");
const ws_1 = require("ws");
/**
 * Canonical JSON: キーをアルファベット順にソートして決定論的なJSON文字列を生成
 */
function canonicalJSON(obj) {
    if (typeof obj !== 'object' || obj === null)
        return JSON.stringify(obj);
    if (Array.isArray(obj))
        return '[' + obj.map(canonicalJSON).join(',') + ']';
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`);
    return '{' + pairs.join(',') + '}';
}
/**
 * パケットをJSON + DELIMITER形式にシリアライズ
 */
function serializePacket(packet) {
    return JSON.stringify(packet) + types_1.DELIMITER;
}
/**
 * TCP/WSSのバッファからパケットを分割して取り出す
 */
class PacketBuffer {
    buffer = '';
    /**
     * データを追加してパースされたパケットを返す
     */
    feed(data) {
        this.buffer += data;
        const parts = this.buffer.split(types_1.DELIMITER);
        this.buffer = parts.pop() || '';
        const packets = [];
        for (const part of parts) {
            if (part.trim()) {
                try {
                    packets.push(JSON.parse(part));
                }
                catch (e) {
                    console.error('[Protocol] JSON parse error:', e);
                }
            }
        }
        return packets;
    }
    /**
     * バッファをクリア
     */
    clear() {
        this.buffer = '';
    }
}
exports.PacketBuffer = PacketBuffer;
/**
 * TCPソケットにパケットを送信
 */
function sendTCP(socket, packet) {
    socket.write(serializePacket(packet));
}
/**
 * WebSocketにパケットを送信
 */
function sendWS(ws, packet) {
    if (ws.readyState === ws_1.WebSocket.OPEN) {
        ws.send(serializePacket(packet));
    }
}
//# sourceMappingURL=protocol.js.map