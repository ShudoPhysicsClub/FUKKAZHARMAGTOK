export class Ed25519 {
    // ── 定数 ──
    static p = 2n ** 255n - 19n;
    static L = 2n ** 252n + 27742317777372353535851937790883648493n;
    static d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
    static SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
    static Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
    static Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
    static G_EXT = [
        Ed25519.Gx,
        Ed25519.Gy,
        1n,
        (Ed25519.Gx * Ed25519.Gy) % Ed25519.p,
    ];
    static ED25519_OID = new Uint8Array([
        0x06, 0x03, 0x2b, 0x65, 0x70,
    ]);
    // ── Fixed-window テーブル (遅延初期化, w=4) ──
    static W = 4;
    static _gTable = null;
    static get gTable() {
        if (!this._gTable) {
            const size = 1 << this.W;
            const t = new Array(size);
            t[0] = [0n, 1n, 1n, 0n];
            t[1] = this.G_EXT;
            for (let i = 2; i < size; i++)
                t[i] = this.extAdd(t[i - 1], this.G_EXT);
            this._gTable = t;
        }
        return this._gTable;
    }
    // ━━━━━━━━━━━━━ 基本演算 ━━━━━━━━━━━━━
    static mod(n, m) {
        const r = n % m;
        return r < 0n ? r + m : r;
    }
    static modInv(a, m) {
        let r0 = m, r1 = a < 0n ? ((a % m) + m) % m : a % m;
        let x0 = 0n, x1 = 1n;
        while (r1 !== 0n) {
            const q = r0 / r1;
            [r0, r1] = [r1, r0 - q * r1];
            [x0, x1] = [x1, x0 - q * x1];
        }
        return x0 < 0n ? x0 + m : x0;
    }
    static modPow(base, exp, m) {
        let result = 1n;
        base = ((base % m) + m) % m;
        while (exp > 0n) {
            if (exp & 1n)
                result = (result * base) % m;
            base = (base * base) % m;
            exp >>= 1n;
        }
        return result;
    }
    // ━━━━━━━━━━━━━ 楕円曲線演算 (Extended 座標) ━━━━━━━━━━━━━
    static extAdd(p1, p2) {
        const P = this.p;
        const [X1, Y1, Z1, T1] = p1;
        const [X2, Y2, Z2, T2] = p2;
        const A = this.mod(X1 * X2, P);
        const B = this.mod(Y1 * Y2, P);
        const C = this.mod(this.mod(this.d * T1, P) * T2, P);
        const D = this.mod(Z1 * Z2, P);
        const E = this.mod(this.mod((X1 + Y1) * (X2 + Y2), P) - A - B, P);
        const F = this.mod(D - C, P);
        const G = this.mod(D + C, P);
        const H = this.mod(B + A, P);
        return [
            this.mod(E * F, P),
            this.mod(G * H, P),
            this.mod(F * G, P),
            this.mod(E * H, P),
        ];
    }
    static extDouble(pt) {
        const P = this.p;
        const [X1, Y1, Z1] = pt;
        const A = this.mod(X1 * X1, P);
        const B = this.mod(Y1 * Y1, P);
        const C = this.mod(2n * ((Z1 * Z1) % P), P);
        const D = this.mod(P - A, P);
        const xpy = this.mod(X1 + Y1, P);
        const E = this.mod(xpy * xpy - A - B, P);
        const G = this.mod(D + B, P);
        const F = this.mod(G - C, P);
        const H = this.mod(D - B, P);
        return [
            this.mod(E * F, P),
            this.mod(G * H, P),
            this.mod(F * G, P),
            this.mod(E * H, P),
        ];
    }
    static extToAffine(pt) {
        const [X, Y, Z] = pt;
        if (Z === 0n)
            return [0n, 1n];
        const zi = this.modInv(Z, this.p);
        return [this.mod(X * zi, this.p), this.mod(Y * zi, this.p)];
    }
    // ━━━━━━━━━━━━━ スカラー乗算 ━━━━━━━━━━━━━
    static scalarMultG(k) {
        const table = this.gTable;
        const mask = BigInt((1 << this.W) - 1);
        const steps = 64;
        let R = [0n, 1n, 1n, 0n];
        for (let i = steps - 1; i >= 0; i--) {
            for (let j = 0; j < this.W; j++)
                R = this.extDouble(R);
            const idx = Number((k >> BigInt(i * this.W)) & mask);
            if (idx !== 0)
                R = this.extAdd(R, table[idx]);
        }
        return R;
    }
    static scalarMult(k, point) {
        let R = [0n, 1n, 1n, 0n];
        let Q = point;
        while (k > 0n) {
            if (k & 1n)
                R = this.extAdd(R, Q);
            Q = this.extDouble(Q);
            k >>= 1n;
        }
        return R;
    }
    static shamirMult(s, k, A) {
        const GA = this.extAdd(this.G_EXT, A);
        let R = [0n, 1n, 1n, 0n];
        for (let i = 255; i >= 0; i--) {
            R = this.extDouble(R);
            const sb = (s >> BigInt(i)) & 1n;
            const kb = (k >> BigInt(i)) & 1n;
            if (sb && kb)
                R = this.extAdd(R, GA);
            else if (sb)
                R = this.extAdd(R, this.G_EXT);
            else if (kb)
                R = this.extAdd(R, A);
        }
        return R;
    }
    // ━━━━━━━━━━━━━ エンコーディング ━━━━━━━━━━━━━
    static pointToBytes(point) {
        const [x, y] = point;
        const out = new Uint8Array(32);
        for (let i = 0; i < 32; i++)
            out[i] = Number((y >> BigInt(i * 8)) & 0xffn);
        if (x & 1n)
            out[31] |= 0x80;
        return out;
    }
    static bytesToPoint(bytes) {
        if (bytes.length !== 32)
            throw new Error("Invalid point encoding");
        let y = 0n;
        for (let i = 0; i < 32; i++)
            y |= BigInt(bytes[i] & (i === 31 ? 0x7f : 0xff)) << BigInt(i * 8);
        if (y >= this.p)
            throw new Error("y coordinate out of range");
        const x_sign = (bytes[31] & 0x80) !== 0;
        const P = this.p;
        const y2 = (y * y) % P;
        const num = this.mod(y2 - 1n, P);
        const den = this.mod(this.d * y2 + 1n, P);
        const x2 = (num * this.modInv(den, P)) % P;
        if (x2 === 0n) {
            if (x_sign)
                throw new Error("Invalid point encoding");
            return [0n, y, 1n, 0n];
        }
        let x = this.modPow(x2, (P + 3n) / 8n, P);
        if ((x * x) % P !== this.mod(x2, P)) {
            x = (x * this.SQRT_M1) % P;
            if ((x * x) % P !== this.mod(x2, P))
                throw new Error("Invalid point: no square root");
        }
        if ((x & 1n) !== (x_sign ? 1n : 0n))
            x = P - x;
        const xc = (x * x) % P;
        const yc = (y * y) % P;
        if (this.mod(yc - xc, P) !==
            this.mod(1n + ((this.d * ((xc * yc) % P)) % P), P))
            throw new Error("Point is not on curve");
        return [x, y, 1n, (x * y) % P];
    }
    static bigIntToBytes(n, len) {
        const out = new Uint8Array(len);
        for (let i = 0; i < len; i++)
            out[i] = Number((n >> BigInt(i * 8)) & 0xffn);
        return out;
    }
    static bytesToBigInt(bytes) {
        let r = 0n;
        for (let i = bytes.length - 1; i >= 0; i--)
            r = (r << 8n) | BigInt(bytes[i]);
        return r;
    }
    // ━━━━━━━━━━━━━ ヘルパー ━━━━━━━━━━━━━
    static async sha512(data) {
        return new Uint8Array(await crypto.subtle.digest("SHA-512", data.buffer));
    }
    static concat(...arrays) {
        let len = 0;
        for (const a of arrays)
            len += a.length;
        const out = new Uint8Array(len);
        let off = 0;
        for (const a of arrays) {
            out.set(a, off);
            off += a.length;
        }
        return out;
    }
    static clamp(s) {
        return (s & ((1n << 255n) - 1n) & ~7n) | (1n << 254n);
    }
    // ━━━━━━━━━━━━━ DERエンコード ━━━━━━━━━━━━━
    static encodeDerLength(len) {
        if (len <= 127)
            return new Uint8Array([len]);
        let bytesNeeded;
        if (len >= 0x1000000)
            bytesNeeded = 4;
        else if (len >= 0x10000)
            bytesNeeded = 3;
        else if (len >= 0x100)
            bytesNeeded = 2;
        else
            bytesNeeded = 1;
        const res = new Uint8Array(bytesNeeded + 1);
        res[0] = 0x80 | bytesNeeded;
        let t = len;
        for (let i = bytesNeeded; i >= 1; i--) {
            res[i] = t & 0xff;
            t >>= 8;
        }
        return res;
    }
    static encodeDerSequence(elements) {
        let total = 0;
        for (const el of elements)
            total += el.length;
        const body = new Uint8Array(total);
        let off = 0;
        for (const el of elements) {
            body.set(el, off);
            off += el.length;
        }
        const len = this.encodeDerLength(body.length);
        const res = new Uint8Array(1 + len.length + body.length);
        res[0] = 0x30;
        res.set(len, 1);
        res.set(body, 1 + len.length);
        return res;
    }
    static encodeDerOctetString(bytes) {
        const len = this.encodeDerLength(bytes.length);
        const res = new Uint8Array(1 + len.length + bytes.length);
        res[0] = 0x04;
        res.set(len, 1);
        res.set(bytes, 1 + len.length);
        return res;
    }
    static encodeDerBitString(bytes) {
        const len = this.encodeDerLength(bytes.length + 1);
        const res = new Uint8Array(1 + len.length + 1 + bytes.length);
        res[0] = 0x03;
        res.set(len, 1);
        res[1 + len.length] = 0x00;
        res.set(bytes, 1 + len.length + 1);
        return res;
    }
    // ━━━━━━━━━━━━━ DERデコード ━━━━━━━━━━━━━
    static parseDerTLV(data, offset) {
        const tag = data[offset++];
        const first = data[offset++];
        let length;
        if (first <= 127) {
            length = first;
        }
        else {
            const n = first & 0x7f;
            length = 0;
            for (let i = 0; i < n; i++)
                length = (length << 8) | data[offset++];
        }
        return {
            tag,
            value: data.subarray(offset, offset + length),
            end: offset + length,
        };
    }
    static parseDerChildren(data) {
        const children = [];
        let offset = 0;
        while (offset < data.length) {
            const tlv = this.parseDerTLV(data, offset);
            children.push({ tag: tlv.tag, value: tlv.value });
            offset = tlv.end;
        }
        return children;
    }
    static unwrapDer(data, expectedTag) {
        const tlv = this.parseDerTLV(data, 0);
        if (tlv.tag !== expectedTag)
            throw new Error(`DER: expected 0x${expectedTag.toString(16)}, got 0x${tlv.tag.toString(16)}`);
        return tlv.value;
    }
    static checkEd25519OID(algSeqValue) {
        const children = this.parseDerChildren(algSeqValue);
        if (children.length === 0 || children[0].tag !== 0x06)
            throw new Error("Expected OID");
        const oid = children[0].value;
        if (oid.length !== 3 ||
            oid[0] !== 0x2b ||
            oid[1] !== 0x65 ||
            oid[2] !== 0x70)
            throw new Error("OID is not Ed25519 (1.3.101.112)");
    }
    // ━━━━━━━━━━━━━ Base64 / PEM ━━━━━━━━━━━━━
    static base64Encode(data) {
        if (typeof Buffer !== "undefined")
            return Buffer.from(data).toString("base64");
        let s = "";
        for (const b of data)
            s += String.fromCharCode(b);
        return btoa(s);
    }
    static base64Decode(str) {
        if (typeof Buffer !== "undefined")
            return new Uint8Array(Buffer.from(str, "base64"));
        const bin = atob(str);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++)
            out[i] = bin.charCodeAt(i);
        return out;
    }
    static pemDecode(pem) {
        return this.base64Decode(pem.replace(/-----.*?-----|\s+/g, ""));
    }
    static pemEncode(der, label) {
        const b64 = this.base64Encode(der);
        const lines = [];
        for (let i = 0; i < b64.length; i += 64)
            lines.push(b64.substring(i, i + 64));
        return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
    }
    // ━━━━━━━━━━━━━ 公開 API (署名) ━━━━━━━━━━━━━
    static async getPublicKey(privateKey) {
        if (privateKey.length !== 32)
            throw new Error("Private key must be 32 bytes");
        const h = await this.sha512(privateKey);
        const s = this.clamp(this.bytesToBigInt(h.subarray(0, 32)));
        return this.pointToBytes(this.extToAffine(this.scalarMultG(s)));
    }
    static async sign(message, privateKey) {
        if (privateKey.length !== 32)
            throw new Error("Private key must be 32 bytes");
        const h = await this.sha512(privateKey);
        const s = this.clamp(this.bytesToBigInt(h.subarray(0, 32)));
        const pubBytes = this.pointToBytes(this.extToAffine(this.scalarMultG(s)));
        const rHash = await this.sha512(this.concat(h.subarray(32, 64), message));
        const r = this.mod(this.bytesToBigInt(rHash), this.L);
        const RBytes = this.pointToBytes(this.extToAffine(this.scalarMultG(r)));
        const kHash = await this.sha512(this.concat(RBytes, pubBytes, message));
        const k = this.mod(this.bytesToBigInt(kHash), this.L);
        const S = this.mod(r + k * s, this.L);
        return this.concat(RBytes, this.bigIntToBytes(S, 32));
    }
    static async verify(signature, message, publicKey) {
        if (signature.length !== 64 || publicKey.length !== 32)
            return false;
        try {
            const RBytes = signature.subarray(0, 32);
            const S = this.bytesToBigInt(signature.subarray(32, 64));
            if (S >= this.L)
                return false;
            const R = this.bytesToPoint(RBytes);
            const A = this.bytesToPoint(publicKey);
            const kHash = await this.sha512(this.concat(RBytes, publicKey, message));
            const k = this.mod(this.bytesToBigInt(kHash), this.L);
            const result = this.shamirMult(S, this.mod(this.L - k, this.L), A);
            const [rx, ry] = this.extToAffine(result);
            const [r0x, r0y] = this.extToAffine(R);
            return rx === r0x && ry === r0y;
        }
        catch {
            return false;
        }
    }
    // ━━━━━━━━━━━━━ 公開 API (PEM) ━━━━━━━━━━━━━
    static privateKeyToPem(raw) {
        if (raw.length !== 32)
            throw new Error("Ed25519 private key must be 32 bytes");
        const version = new Uint8Array([0x02, 0x01, 0x00]);
        const algId = this.encodeDerSequence([this.ED25519_OID]);
        const keyOctet = this.encodeDerOctetString(this.encodeDerOctetString(raw));
        return this.pemEncode(this.encodeDerSequence([version, algId, keyOctet]), "PRIVATE KEY");
    }
    static pemToPrivateKey(pem) {
        const outer = this.unwrapDer(this.pemDecode(pem), 0x30);
        const children = this.parseDerChildren(outer);
        if (children.length < 3)
            throw new Error("Invalid PKCS#8");
        this.checkEd25519OID(children[1].value);
        if (children[2].tag !== 0x04)
            throw new Error("Expected OCTET STRING");
        const inner = this.unwrapDer(children[2].value, 0x04);
        if (inner.length !== 32)
            throw new Error(`Expected 32 bytes, got ${inner.length}`);
        return new Uint8Array(inner);
    }
    static publicKeyToPem(raw) {
        if (raw.length !== 32)
            throw new Error("Ed25519 public key must be 32 bytes");
        const algId = this.encodeDerSequence([this.ED25519_OID]);
        const bitStr = this.encodeDerBitString(raw);
        return this.pemEncode(this.encodeDerSequence([algId, bitStr]), "PUBLIC KEY");
    }
    static pemToPublicKey(pem) {
        const outer = this.unwrapDer(this.pemDecode(pem), 0x30);
        const children = this.parseDerChildren(outer);
        if (children.length < 2)
            throw new Error("Invalid SPKI");
        this.checkEd25519OID(children[0].value);
        if (children[1].tag !== 0x03)
            throw new Error("Expected BIT STRING");
        const bits = children[1].value;
        if (bits[0] !== 0x00)
            throw new Error("BIT STRING unused bits must be 0");
        const pub = bits.subarray(1);
        if (pub.length !== 32)
            throw new Error(`Expected 32 bytes, got ${pub.length}`);
        return new Uint8Array(pub);
    }
}
//# sourceMappingURL=crypto.js.map