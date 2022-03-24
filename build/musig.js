(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
    typeof define === 'function' && define.amd ? define(['exports'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.musig = {}));
})(this, (function (exports) { 'use strict';

    const nodeCrypto = {};

    /*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
    const _0n$1 = BigInt(0);
    const _1n$1 = BigInt(1);
    const _2n = BigInt(2);
    const _3n = BigInt(3);
    const _8n = BigInt(8);
    const POW_2_256$1 = _2n ** BigInt(256);
    const CURVE = {
        a: _0n$1,
        b: BigInt(7),
        P: POW_2_256$1 - _2n ** BigInt(32) - BigInt(977),
        n: POW_2_256$1 - BigInt('432420386565659656852420866394968145599'),
        h: _1n$1,
        Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
        Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
        beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
    };
    function weistrass(x) {
        const { a, b } = CURVE;
        const x2 = mod$1(x * x);
        const x3 = mod$1(x2 * x);
        return mod$1(x3 + a * x + b);
    }
    const USE_ENDOMORPHISM = CURVE.a === _0n$1;
    class JacobianPoint {
        constructor(x, y, z) {
            this.x = x;
            this.y = y;
            this.z = z;
        }
        static fromAffine(p) {
            if (!(p instanceof Point)) {
                throw new TypeError('JacobianPoint#fromAffine: expected Point');
            }
            return new JacobianPoint(p.x, p.y, _1n$1);
        }
        static toAffineBatch(points) {
            const toInv = invertBatch(points.map((p) => p.z));
            return points.map((p, i) => p.toAffine(toInv[i]));
        }
        static normalizeZ(points) {
            return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
        }
        equals(other) {
            if (!(other instanceof JacobianPoint))
                throw new TypeError('JacobianPoint expected');
            const { x: X1, y: Y1, z: Z1 } = this;
            const { x: X2, y: Y2, z: Z2 } = other;
            const Z1Z1 = mod$1(Z1 ** _2n);
            const Z2Z2 = mod$1(Z2 ** _2n);
            const U1 = mod$1(X1 * Z2Z2);
            const U2 = mod$1(X2 * Z1Z1);
            const S1 = mod$1(mod$1(Y1 * Z2) * Z2Z2);
            const S2 = mod$1(mod$1(Y2 * Z1) * Z1Z1);
            return U1 === U2 && S1 === S2;
        }
        negate() {
            return new JacobianPoint(this.x, mod$1(-this.y), this.z);
        }
        double() {
            const { x: X1, y: Y1, z: Z1 } = this;
            const A = mod$1(X1 ** _2n);
            const B = mod$1(Y1 ** _2n);
            const C = mod$1(B ** _2n);
            const D = mod$1(_2n * (mod$1((X1 + B) ** _2n) - A - C));
            const E = mod$1(_3n * A);
            const F = mod$1(E ** _2n);
            const X3 = mod$1(F - _2n * D);
            const Y3 = mod$1(E * (D - X3) - _8n * C);
            const Z3 = mod$1(_2n * Y1 * Z1);
            return new JacobianPoint(X3, Y3, Z3);
        }
        add(other) {
            if (!(other instanceof JacobianPoint))
                throw new TypeError('JacobianPoint expected');
            const { x: X1, y: Y1, z: Z1 } = this;
            const { x: X2, y: Y2, z: Z2 } = other;
            if (X2 === _0n$1 || Y2 === _0n$1)
                return this;
            if (X1 === _0n$1 || Y1 === _0n$1)
                return other;
            const Z1Z1 = mod$1(Z1 ** _2n);
            const Z2Z2 = mod$1(Z2 ** _2n);
            const U1 = mod$1(X1 * Z2Z2);
            const U2 = mod$1(X2 * Z1Z1);
            const S1 = mod$1(mod$1(Y1 * Z2) * Z2Z2);
            const S2 = mod$1(mod$1(Y2 * Z1) * Z1Z1);
            const H = mod$1(U2 - U1);
            const r = mod$1(S2 - S1);
            if (H === _0n$1) {
                if (r === _0n$1) {
                    return this.double();
                }
                else {
                    return JacobianPoint.ZERO;
                }
            }
            const HH = mod$1(H ** _2n);
            const HHH = mod$1(H * HH);
            const V = mod$1(U1 * HH);
            const X3 = mod$1(r ** _2n - HHH - _2n * V);
            const Y3 = mod$1(r * (V - X3) - S1 * HHH);
            const Z3 = mod$1(Z1 * Z2 * H);
            return new JacobianPoint(X3, Y3, Z3);
        }
        subtract(other) {
            return this.add(other.negate());
        }
        multiplyUnsafe(scalar) {
            let n = normalizeScalar(scalar);
            const P0 = JacobianPoint.ZERO;
            if (n === _0n$1)
                return P0;
            if (n === _1n$1)
                return this;
            if (!USE_ENDOMORPHISM) {
                let p = P0;
                let d = this;
                while (n > _0n$1) {
                    if (n & _1n$1)
                        p = p.add(d);
                    d = d.double();
                    n >>= _1n$1;
                }
                return p;
            }
            let { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
            let k1p = P0;
            let k2p = P0;
            let d = this;
            while (k1 > _0n$1 || k2 > _0n$1) {
                if (k1 & _1n$1)
                    k1p = k1p.add(d);
                if (k2 & _1n$1)
                    k2p = k2p.add(d);
                d = d.double();
                k1 >>= _1n$1;
                k2 >>= _1n$1;
            }
            if (k1neg)
                k1p = k1p.negate();
            if (k2neg)
                k2p = k2p.negate();
            k2p = new JacobianPoint(mod$1(k2p.x * CURVE.beta), k2p.y, k2p.z);
            return k1p.add(k2p);
        }
        precomputeWindow(W) {
            const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
            const points = [];
            let p = this;
            let base = p;
            for (let window = 0; window < windows; window++) {
                base = p;
                points.push(base);
                for (let i = 1; i < 2 ** (W - 1); i++) {
                    base = base.add(p);
                    points.push(base);
                }
                p = base.double();
            }
            return points;
        }
        wNAF(n, affinePoint) {
            if (!affinePoint && this.equals(JacobianPoint.BASE))
                affinePoint = Point.BASE;
            const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
            if (256 % W) {
                throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
            }
            let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
            if (!precomputes) {
                precomputes = this.precomputeWindow(W);
                if (affinePoint && W !== 1) {
                    precomputes = JacobianPoint.normalizeZ(precomputes);
                    pointPrecomputes.set(affinePoint, precomputes);
                }
            }
            let p = JacobianPoint.ZERO;
            let f = JacobianPoint.ZERO;
            const windows = 1 + (USE_ENDOMORPHISM ? 128 / W : 256 / W);
            const windowSize = 2 ** (W - 1);
            const mask = BigInt(2 ** W - 1);
            const maxNumber = 2 ** W;
            const shiftBy = BigInt(W);
            for (let window = 0; window < windows; window++) {
                const offset = window * windowSize;
                let wbits = Number(n & mask);
                n >>= shiftBy;
                if (wbits > windowSize) {
                    wbits -= maxNumber;
                    n += _1n$1;
                }
                if (wbits === 0) {
                    let pr = precomputes[offset];
                    if (window % 2)
                        pr = pr.negate();
                    f = f.add(pr);
                }
                else {
                    let cached = precomputes[offset + Math.abs(wbits) - 1];
                    if (wbits < 0)
                        cached = cached.negate();
                    p = p.add(cached);
                }
            }
            return { p, f };
        }
        multiply(scalar, affinePoint) {
            let n = normalizeScalar(scalar);
            let point;
            let fake;
            if (USE_ENDOMORPHISM) {
                const { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
                let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
                let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
                if (k1neg)
                    k1p = k1p.negate();
                if (k2neg)
                    k2p = k2p.negate();
                k2p = new JacobianPoint(mod$1(k2p.x * CURVE.beta), k2p.y, k2p.z);
                point = k1p.add(k2p);
                fake = f1p.add(f2p);
            }
            else {
                const { p, f } = this.wNAF(n, affinePoint);
                point = p;
                fake = f;
            }
            return JacobianPoint.normalizeZ([point, fake])[0];
        }
        toAffine(invZ = invert(this.z)) {
            const { x, y, z } = this;
            const iz1 = invZ;
            const iz2 = mod$1(iz1 * iz1);
            const iz3 = mod$1(iz2 * iz1);
            const ax = mod$1(x * iz2);
            const ay = mod$1(y * iz3);
            const zz = mod$1(z * iz1);
            if (zz !== _1n$1)
                throw new Error('invZ was invalid');
            return new Point(ax, ay);
        }
    }
    JacobianPoint.BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n$1);
    JacobianPoint.ZERO = new JacobianPoint(_0n$1, _1n$1, _0n$1);
    const pointPrecomputes = new WeakMap();
    class Point {
        constructor(x, y) {
            this.x = x;
            this.y = y;
        }
        _setWindowSize(windowSize) {
            this._WINDOW_SIZE = windowSize;
            pointPrecomputes.delete(this);
        }
        static fromCompressedHex(bytes) {
            const isShort = bytes.length === 32;
            const x = bytesToNumber$1(isShort ? bytes : bytes.subarray(1));
            if (!isValidFieldElement$1(x))
                throw new Error('Point is not on curve');
            const y2 = weistrass(x);
            let y = sqrtMod(y2);
            const isYOdd = (y & _1n$1) === _1n$1;
            if (isShort) {
                if (isYOdd)
                    y = mod$1(-y);
            }
            else {
                const isFirstByteOdd = (bytes[0] & 1) === 1;
                if (isFirstByteOdd !== isYOdd)
                    y = mod$1(-y);
            }
            const point = new Point(x, y);
            point.assertValidity();
            return point;
        }
        static fromUncompressedHex(bytes) {
            const x = bytesToNumber$1(bytes.subarray(1, 33));
            const y = bytesToNumber$1(bytes.subarray(33, 65));
            const point = new Point(x, y);
            point.assertValidity();
            return point;
        }
        static fromHex(hex) {
            const bytes = ensureBytes$1(hex);
            const len = bytes.length;
            const header = bytes[0];
            if (len === 32 || (len === 33 && (header === 0x02 || header === 0x03))) {
                return this.fromCompressedHex(bytes);
            }
            if (len === 65 && header === 0x04)
                return this.fromUncompressedHex(bytes);
            throw new Error(`Point.fromHex: received invalid point. Expected 32-33 compressed bytes or 65 uncompressed bytes, not ${len}`);
        }
        static fromPrivateKey(privateKey) {
            return Point.BASE.multiply(normalizePrivateKey$1(privateKey));
        }
        static fromSignature(msgHash, signature, recovery) {
            msgHash = ensureBytes$1(msgHash);
            const h = truncateHash(msgHash);
            const { r, s } = normalizeSignature(signature);
            if (recovery !== 0 && recovery !== 1) {
                throw new Error('Cannot recover signature: invalid recovery bit');
            }
            if (h === _0n$1)
                throw new Error('Cannot recover signature: msgHash cannot be 0');
            const prefix = recovery & 1 ? '03' : '02';
            const R = Point.fromHex(prefix + numTo32bStr$1(r));
            const { n } = CURVE;
            const rinv = invert(r, n);
            const u1 = mod$1(-h * rinv, n);
            const u2 = mod$1(s * rinv, n);
            const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
            if (!Q)
                throw new Error('Cannot recover signature: point at infinify');
            Q.assertValidity();
            return Q;
        }
        toRawBytes(isCompressed = false) {
            return hexToBytes$1(this.toHex(isCompressed));
        }
        toHex(isCompressed = false) {
            const x = numTo32bStr$1(this.x);
            if (isCompressed) {
                const prefix = this.y & _1n$1 ? '03' : '02';
                return `${prefix}${x}`;
            }
            else {
                return `04${x}${numTo32bStr$1(this.y)}`;
            }
        }
        toHexX() {
            return this.toHex(true).slice(2);
        }
        toRawX() {
            return this.toRawBytes(true).slice(1);
        }
        assertValidity() {
            const msg = 'Point is not on elliptic curve';
            const { x, y } = this;
            if (!isValidFieldElement$1(x) || !isValidFieldElement$1(y))
                throw new Error(msg);
            const left = mod$1(y * y);
            const right = weistrass(x);
            if (mod$1(left - right) !== _0n$1)
                throw new Error(msg);
        }
        equals(other) {
            return this.x === other.x && this.y === other.y;
        }
        negate() {
            return new Point(this.x, mod$1(-this.y));
        }
        double() {
            return JacobianPoint.fromAffine(this).double().toAffine();
        }
        add(other) {
            return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
        }
        subtract(other) {
            return this.add(other.negate());
        }
        multiply(scalar) {
            return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
        }
        multiplyAndAddUnsafe(Q, a, b) {
            const P = JacobianPoint.fromAffine(this);
            const aP = P.multiply(a);
            const bQ = JacobianPoint.fromAffine(Q).multiplyUnsafe(b);
            const sum = aP.add(bQ);
            return sum.equals(JacobianPoint.ZERO) ? undefined : sum.toAffine();
        }
    }
    Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
    Point.ZERO = new Point(_0n$1, _0n$1);
    function sliceDER(s) {
        return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
    }
    function parseDERInt(data) {
        if (data.length < 2 || data[0] !== 0x02) {
            throw new Error(`Invalid signature integer tag: ${bytesToHex$1(data)}`);
        }
        const len = data[1];
        const res = data.subarray(2, len + 2);
        if (!len || res.length !== len) {
            throw new Error(`Invalid signature integer: wrong length`);
        }
        if (res[0] === 0x00 && res[1] <= 0x7f) {
            throw new Error('Invalid signature integer: trailing length');
        }
        return { data: bytesToNumber$1(res), left: data.subarray(len + 2) };
    }
    function parseDERSignature(data) {
        if (data.length < 2 || data[0] != 0x30) {
            throw new Error(`Invalid signature tag: ${bytesToHex$1(data)}`);
        }
        if (data[1] !== data.length - 2) {
            throw new Error('Invalid signature: incorrect length');
        }
        const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
        const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
        if (rBytesLeft.length) {
            throw new Error(`Invalid signature: left bytes after parsing: ${bytesToHex$1(rBytesLeft)}`);
        }
        return { r, s };
    }
    class Signature {
        constructor(r, s) {
            this.r = r;
            this.s = s;
            this.assertValidity();
        }
        static fromCompact(hex) {
            const arr = isUint8a$1(hex);
            const name = 'Signature.fromCompact';
            if (typeof hex !== 'string' && !arr)
                throw new TypeError(`${name}: Expected string or Uint8Array`);
            const str = arr ? bytesToHex$1(hex) : hex;
            if (str.length !== 128)
                throw new Error(`${name}: Expected 64-byte hex`);
            return new Signature(hexToNumber$1(str.slice(0, 64)), hexToNumber$1(str.slice(64, 128)));
        }
        static fromDER(hex) {
            const arr = isUint8a$1(hex);
            if (typeof hex !== 'string' && !arr)
                throw new TypeError(`Signature.fromDER: Expected string or Uint8Array`);
            const { r, s } = parseDERSignature(arr ? hex : hexToBytes$1(hex));
            return new Signature(r, s);
        }
        static fromHex(hex) {
            return this.fromDER(hex);
        }
        assertValidity() {
            const { r, s } = this;
            if (!isWithinCurveOrder$1(r))
                throw new Error('Invalid Signature: r must be 0 < r < n');
            if (!isWithinCurveOrder$1(s))
                throw new Error('Invalid Signature: s must be 0 < s < n');
        }
        hasHighS() {
            const HALF = CURVE.n >> _1n$1;
            return this.s > HALF;
        }
        normalizeS() {
            return this.hasHighS() ? new Signature(this.r, CURVE.n - this.s) : this;
        }
        toDERRawBytes(isCompressed = false) {
            return hexToBytes$1(this.toDERHex(isCompressed));
        }
        toDERHex(isCompressed = false) {
            const sHex = sliceDER(numberToHexUnpadded(this.s));
            if (isCompressed)
                return sHex;
            const rHex = sliceDER(numberToHexUnpadded(this.r));
            const rLen = numberToHexUnpadded(rHex.length / 2);
            const sLen = numberToHexUnpadded(sHex.length / 2);
            const length = numberToHexUnpadded(rHex.length / 2 + sHex.length / 2 + 4);
            return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
        }
        toRawBytes() {
            return this.toDERRawBytes();
        }
        toHex() {
            return this.toDERHex();
        }
        toCompactRawBytes() {
            return hexToBytes$1(this.toCompactHex());
        }
        toCompactHex() {
            return numTo32bStr$1(this.r) + numTo32bStr$1(this.s);
        }
    }
    function concatBytes$1(...arrays) {
        if (!arrays.every(isUint8a$1))
            throw new Error('Uint8Array list expected');
        if (arrays.length === 1)
            return arrays[0];
        const length = arrays.reduce((a, arr) => a + arr.length, 0);
        const result = new Uint8Array(length);
        for (let i = 0, pad = 0; i < arrays.length; i++) {
            const arr = arrays[i];
            result.set(arr, pad);
            pad += arr.length;
        }
        return result;
    }
    function isUint8a$1(bytes) {
        return bytes instanceof Uint8Array;
    }
    const hexes$1 = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    function bytesToHex$1(uint8a) {
        if (!(uint8a instanceof Uint8Array))
            throw new Error('Expected Uint8Array');
        let hex = '';
        for (let i = 0; i < uint8a.length; i++) {
            hex += hexes$1[uint8a[i]];
        }
        return hex;
    }
    function numTo32bStr$1(num) {
        if (num > POW_2_256$1)
            throw new Error('Expected number < 2^256');
        return num.toString(16).padStart(64, '0');
    }
    function numTo32b$1(num) {
        return hexToBytes$1(numTo32bStr$1(num));
    }
    function numberToHexUnpadded(num) {
        const hex = num.toString(16);
        return hex.length & 1 ? `0${hex}` : hex;
    }
    function hexToNumber$1(hex) {
        if (typeof hex !== 'string') {
            throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
        }
        return BigInt(`0x${hex}`);
    }
    function hexToBytes$1(hex) {
        if (typeof hex !== 'string') {
            throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
        }
        if (hex.length % 2)
            throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
        const array = new Uint8Array(hex.length / 2);
        for (let i = 0; i < array.length; i++) {
            const j = i * 2;
            const hexByte = hex.slice(j, j + 2);
            const byte = Number.parseInt(hexByte, 16);
            if (Number.isNaN(byte) || byte < 0)
                throw new Error('Invalid byte sequence');
            array[i] = byte;
        }
        return array;
    }
    function bytesToNumber$1(bytes) {
        return hexToNumber$1(bytesToHex$1(bytes));
    }
    function ensureBytes$1(hex) {
        return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes$1(hex);
    }
    function normalizeScalar(num) {
        if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0)
            return BigInt(num);
        if (typeof num === 'bigint' && isWithinCurveOrder$1(num))
            return num;
        throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
    }
    function mod$1(a, b = CURVE.P) {
        const result = a % b;
        return result >= _0n$1 ? result : b + result;
    }
    function pow2(x, power) {
        const { P } = CURVE;
        let res = x;
        while (power-- > _0n$1) {
            res *= res;
            res %= P;
        }
        return res;
    }
    function sqrtMod(x) {
        const { P } = CURVE;
        const _6n = BigInt(6);
        const _11n = BigInt(11);
        const _22n = BigInt(22);
        const _23n = BigInt(23);
        const _44n = BigInt(44);
        const _88n = BigInt(88);
        const b2 = (x * x * x) % P;
        const b3 = (b2 * b2 * x) % P;
        const b6 = (pow2(b3, _3n) * b3) % P;
        const b9 = (pow2(b6, _3n) * b3) % P;
        const b11 = (pow2(b9, _2n) * b2) % P;
        const b22 = (pow2(b11, _11n) * b11) % P;
        const b44 = (pow2(b22, _22n) * b22) % P;
        const b88 = (pow2(b44, _44n) * b44) % P;
        const b176 = (pow2(b88, _88n) * b88) % P;
        const b220 = (pow2(b176, _44n) * b44) % P;
        const b223 = (pow2(b220, _3n) * b3) % P;
        const t1 = (pow2(b223, _23n) * b22) % P;
        const t2 = (pow2(t1, _6n) * b2) % P;
        return pow2(t2, _2n);
    }
    function invert(number, modulo = CURVE.P) {
        if (number === _0n$1 || modulo <= _0n$1) {
            throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
        }
        let a = mod$1(number, modulo);
        let b = modulo;
        let x = _0n$1, u = _1n$1;
        while (a !== _0n$1) {
            const q = b / a;
            const r = b % a;
            const m = x - u * q;
            b = a, a = r, x = u, u = m;
        }
        const gcd = b;
        if (gcd !== _1n$1)
            throw new Error('invert: does not exist');
        return mod$1(x, modulo);
    }
    function invertBatch(nums, p = CURVE.P) {
        const scratch = new Array(nums.length);
        const lastMultiplied = nums.reduce((acc, num, i) => {
            if (num === _0n$1)
                return acc;
            scratch[i] = acc;
            return mod$1(acc * num, p);
        }, _1n$1);
        const inverted = invert(lastMultiplied, p);
        nums.reduceRight((acc, num, i) => {
            if (num === _0n$1)
                return acc;
            scratch[i] = mod$1(acc * scratch[i], p);
            return mod$1(acc * num, p);
        }, inverted);
        return scratch;
    }
    const divNearest = (a, b) => (a + b / _2n) / b;
    const POW_2_128 = _2n ** BigInt(128);
    function splitScalarEndo(k) {
        const { n } = CURVE;
        const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
        const b1 = -_1n$1 * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
        const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
        const b2 = a1;
        const c1 = divNearest(b2 * k, n);
        const c2 = divNearest(-b1 * k, n);
        let k1 = mod$1(k - c1 * a1 - c2 * a2, n);
        let k2 = mod$1(-c1 * b1 - c2 * b2, n);
        const k1neg = k1 > POW_2_128;
        const k2neg = k2 > POW_2_128;
        if (k1neg)
            k1 = n - k1;
        if (k2neg)
            k2 = n - k2;
        if (k1 > POW_2_128 || k2 > POW_2_128) {
            throw new Error('splitScalarEndo: Endomorphism failed, k=' + k);
        }
        return { k1neg, k1, k2neg, k2 };
    }
    function truncateHash(hash) {
        const { n } = CURVE;
        const byteLength = hash.length;
        const delta = byteLength * 8 - 256;
        let h = bytesToNumber$1(hash);
        if (delta > 0)
            h = h >> BigInt(delta);
        if (h >= n)
            h -= n;
        return h;
    }
    function isWithinCurveOrder$1(num) {
        return _0n$1 < num && num < CURVE.n;
    }
    function isValidFieldElement$1(num) {
        return _0n$1 < num && num < CURVE.P;
    }
    function normalizePrivateKey$1(key) {
        let num;
        if (typeof key === 'bigint') {
            num = key;
        }
        else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
            num = BigInt(key);
        }
        else if (typeof key === 'string') {
            if (key.length !== 64)
                throw new Error('Expected 32 bytes of private key');
            num = hexToNumber$1(key);
        }
        else if (isUint8a$1(key)) {
            if (key.length !== 32)
                throw new Error('Expected 32 bytes of private key');
            num = bytesToNumber$1(key);
        }
        else {
            throw new TypeError('Expected valid private key');
        }
        if (!isWithinCurveOrder$1(num))
            throw new Error('Expected private key: 0 < key < n');
        return num;
    }
    function normalizeSignature(signature) {
        if (signature instanceof Signature) {
            signature.assertValidity();
            return signature;
        }
        try {
            return Signature.fromDER(signature);
        }
        catch (error) {
            return Signature.fromCompact(signature);
        }
    }
    Point.BASE._setWindowSize(8);
    const crypto = {
        node: nodeCrypto,
        web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
    };
    const TAGGED_HASH_PREFIXES = {};
    const utils = {
        isValidPrivateKey(privateKey) {
            try {
                normalizePrivateKey$1(privateKey);
                return true;
            }
            catch (error) {
                return false;
            }
        },
        privateAdd: (privateKey, tweak) => {
            const p = normalizePrivateKey$1(privateKey);
            const t = bytesToNumber$1(ensureBytes$1(tweak));
            return numTo32b$1(mod$1(p + t, CURVE.n));
        },
        privateNegate: (privateKey) => {
            const p = normalizePrivateKey$1(privateKey);
            return numTo32b$1(CURVE.n - p);
        },
        pointAddScalar: (p, tweak, isCompressed) => {
            const P = Point.fromHex(p);
            const t = bytesToNumber$1(ensureBytes$1(tweak));
            const Q = Point.BASE.multiplyAndAddUnsafe(P, t, _1n$1);
            if (!Q)
                throw new Error('Tweaked point at infinity');
            return Q.toRawBytes(isCompressed);
        },
        pointMultiply: (p, tweak, isCompressed) => {
            const P = Point.fromHex(p);
            const t = bytesToNumber$1(ensureBytes$1(tweak));
            return P.multiply(t).toRawBytes(isCompressed);
        },
        hashToPrivateKey: (hash) => {
            hash = ensureBytes$1(hash);
            if (hash.length < 40 || hash.length > 1024)
                throw new Error('Expected 40-1024 bytes of private key as per FIPS 186');
            const num = mod$1(bytesToNumber$1(hash), CURVE.n);
            if (num === _0n$1 || num === _1n$1)
                throw new Error('Invalid private key');
            return numTo32b$1(num);
        },
        randomBytes: (bytesLength = 32) => {
            if (crypto.web) {
                return crypto.web.getRandomValues(new Uint8Array(bytesLength));
            }
            else if (crypto.node) {
                const { randomBytes } = crypto.node;
                return Uint8Array.from(randomBytes(bytesLength));
            }
            else {
                throw new Error("The environment doesn't have randomBytes function");
            }
        },
        randomPrivateKey: () => {
            return utils.hashToPrivateKey(utils.randomBytes(40));
        },
        bytesToHex: bytesToHex$1,
        mod: mod$1,
        sha256: async (...messages) => {
            if (crypto.web) {
                const buffer = await crypto.web.subtle.digest('SHA-256', concatBytes$1(...messages));
                return new Uint8Array(buffer);
            }
            else if (crypto.node) {
                const { createHash } = crypto.node;
                const hash = createHash('sha256');
                messages.forEach((m) => hash.update(m));
                return Uint8Array.from(hash.digest());
            }
            else {
                throw new Error("The environment doesn't have sha256 function");
            }
        },
        hmacSha256: async (key, ...messages) => {
            if (crypto.web) {
                const ckey = await crypto.web.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
                const message = concatBytes$1(...messages);
                const buffer = await crypto.web.subtle.sign('HMAC', ckey, message);
                return new Uint8Array(buffer);
            }
            else if (crypto.node) {
                const { createHmac } = crypto.node;
                const hash = createHmac('sha256', key);
                messages.forEach((m) => hash.update(m));
                return Uint8Array.from(hash.digest());
            }
            else {
                throw new Error("The environment doesn't have hmac-sha256 function");
            }
        },
        sha256Sync: undefined,
        hmacSha256Sync: undefined,
        taggedHash: async (tag, ...messages) => {
            let tagP = TAGGED_HASH_PREFIXES[tag];
            if (tagP === undefined) {
                const tagH = await utils.sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
                tagP = concatBytes$1(tagH, tagH);
                TAGGED_HASH_PREFIXES[tag] = tagP;
            }
            return utils.sha256(tagP, ...messages);
        },
        taggedHashSync: (tag, ...messages) => {
            throw new Error('utils.sha256Sync is undefined, you need to set it');
        },
        precompute(windowSize = 8, point = Point.BASE) {
            const cached = point === Point.BASE ? point : new Point(point.x, point.y);
            cached._setWindowSize(windowSize);
            cached.multiply(_3n);
            return cached;
        },
    };

    /*! musig-js - MIT License (c) 2022 Brandon Black */
    const _0n = BigInt(0);
    const _1n = BigInt(1);
    const POW_2_256 = BigInt(2) ** BigInt(256);
    function concatBytes(...arrays) {
        if (arrays.length === 1)
            return arrays[0];
        const length = arrays.reduce((a, arr) => a + arr.length, 0);
        const result = new Uint8Array(length);
        for (let i = 0, pad = 0; i < arrays.length; i++) {
            const arr = arrays[i];
            result.set(arr, pad);
            pad += arr.length;
        }
        return result;
    }
    function isUint8a(bytes) {
        return bytes instanceof Uint8Array;
    }
    const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
    function bytesToHex(uint8a) {
        if (!(uint8a instanceof Uint8Array))
            throw new Error('Expected Uint8Array');
        let hex = '';
        for (let i = 0; i < uint8a.length; i++) {
            hex += hexes[uint8a[i]];
        }
        return hex;
    }
    function numTo32bStr(num) {
        if (num > POW_2_256)
            throw new Error('Expected number < 2^256');
        return num.toString(16).padStart(64, '0');
    }
    function numTo32b(num) {
        return hexToBytes(numTo32bStr(num));
    }
    function hexToNumber(hex) {
        if (typeof hex !== 'string') {
            throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
        }
        return BigInt(`0x${hex}`);
    }
    function hexToBytes(hex) {
        if (typeof hex !== 'string') {
            throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
        }
        if (hex.length % 2)
            throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
        const array = new Uint8Array(hex.length / 2);
        for (let i = 0; i < array.length; i++) {
            const j = i * 2;
            const hexByte = hex.slice(j, j + 2);
            const byte = Number.parseInt(hexByte, 16);
            if (Number.isNaN(byte) || byte < 0)
                throw new Error('Invalid byte sequence');
            array[i] = byte;
        }
        return array;
    }
    function bytesToNumber(bytes) {
        return hexToNumber(bytesToHex(bytes));
    }
    function ensureBytes(hex) {
        return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
    }
    function mod(a, b = CURVE.P) {
        const result = a % b;
        return result >= _0n ? result : b + result;
    }
    function isWithinCurveOrder(num) {
        return _0n < num && num < CURVE.n;
    }
    function isValidFieldElement(num) {
        return _0n < num && num < CURVE.P;
    }
    function normalizePrivateKey(key) {
        let num;
        if (typeof key === 'bigint') {
            num = key;
        }
        else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
            num = BigInt(key);
        }
        else if (typeof key === 'string') {
            if (key.length !== 64)
                throw new Error('Expected 32 bytes of private key');
            num = hexToNumber(key);
        }
        else if (isUint8a(key)) {
            if (key.length !== 32)
                throw new Error('Expected 32 bytes of private key');
            num = bytesToNumber(key);
        }
        else {
            throw new TypeError('Expected valid private key');
        }
        if (!isWithinCurveOrder(num))
            throw new Error('Expected private key: 0 < key < n');
        return num;
    }
    function normalizePublicKey(publicKey) {
        if (publicKey instanceof Point) {
            publicKey.assertValidity();
            return publicKey;
        }
        else {
            return Point.fromHex(publicKey);
        }
    }
    function hasEvenY(point) {
        return (point.y & _1n) === _0n;
    }
    function normalize32b(p) {
        if (p instanceof Point)
            p = p.x;
        if (typeof p === 'number') {
            if (Number.isSafeInteger(p))
                throw new Error(`Expected integer, got ${p}`);
            p = BigInt(p);
        }
        if (typeof p === 'bigint') {
            return numTo32b(p);
        }
        const b = ensureBytes(p);
        return b.subarray(b.length - 32);
    }
    function normalize33b(p) {
        if (p instanceof Point)
            return p.toRawBytes(true);
        return ensureBytes(p);
    }
    function normalizeEvenPublicKey(pubKey) {
        const publicKey = normalizePublicKey(pubKey);
        return hasEvenY(publicKey) ? publicKey : publicKey.negate();
    }
    function normalizeMusigPrivateNonce(privateNonce) {
        if (!Array.isArray(privateNonce) || privateNonce.length !== 2) {
            const privateNonceB = ensureBytes(privateNonce);
            privateNonce = [privateNonceB.subarray(0, 32), privateNonceB.subarray(32)];
        }
        return [normalizePrivateKey(privateNonce[0]), normalizePrivateKey(privateNonce[0])];
    }
    function normalizeMusigPublicNonce(publicNonce) {
        if (!Array.isArray(publicNonce) || publicNonce.length !== 2) {
            const publicNonceB = ensureBytes(publicNonce);
            publicNonce = [publicNonceB.subarray(0, 33), publicNonceB.subarray(33)];
        }
        return [normalizePublicKey(publicNonce[0]), normalizePublicKey(publicNonce[0])];
    }
    function musigPublicNonceToBytes(publicNonce) {
        if (Array.isArray(publicNonce) && publicNonce.length === 2) {
            const publicNonceBytes = new Uint8Array(publicNonce.length * 33);
            for (let i = 0; i < publicNonce.length; i++) {
                publicNonceBytes.set(normalize33b(publicNonce[i]), i * 33);
            }
            return publicNonceBytes;
        }
        return ensureBytes(publicNonce);
    }
    class MusigKeyAggCache {
        constructor(publicKeyHash, secondPublicKeyX, publicKey = Point.ZERO, parityFactor = true, tweak = _0n, _coefCache = new Map()) {
            this.publicKeyHash = publicKeyHash;
            this.secondPublicKeyX = secondPublicKeyX;
            this.publicKey = publicKey;
            this.parityFactor = parityFactor;
            this.tweak = tweak;
            this._coefCache = _coefCache;
        }
        copyWith(publicKey, parityFactor, tweak) {
            const cache = new MusigKeyAggCache(this.publicKeyHash, this.secondPublicKeyX, publicKey, parityFactor, tweak, this._coefCache);
            cache.assertValidity();
            return cache;
        }
        static *fromPublicKeys(pubKeys) {
            const publicKeys = pubKeys.map((publicKey) => normalizeEvenPublicKey(publicKey));
            publicKeys.sort((a, b) => (a.x > b.x ? 1 : -1));
            const secondPublicKey = publicKeys.find((pk) => !publicKeys[0].equals(pk)) || Point.ZERO;
            const publicKeyHash = yield* taggedHash(TAGS.keyagg_list, ...publicKeys.map((pk) => pk.toRawX()));
            const cache = new MusigKeyAggCache(publicKeyHash, secondPublicKey.x);
            let publicKey = Point.ZERO;
            for (const pk of publicKeys) {
                publicKey = publicKey.add(pk.multiply(yield* cache.coefficient(pk)));
            }
            return cache.copyWith(publicKey, !hasEvenY(publicKey));
        }
        assertValidity() {
            this.publicKey.assertValidity();
            if (this.publicKeyHash.length !== 32 ||
                (this.secondPublicKeyX !== _0n && !isValidFieldElement(this.secondPublicKeyX)) ||
                (this.tweak !== _0n && !isWithinCurveOrder(this.tweak)))
                throw new Error('Invalid KeyAggCache');
        }
        *coefficient(publicKey) {
            if (publicKey.x === this.secondPublicKeyX)
                return _1n;
            let coef = this._coefCache.get(publicKey.x);
            if (coef === undefined) {
                coef = bytesToNumber(yield* taggedHash(TAGS.keyagg_coef, this.publicKeyHash, publicKey.toRawX()));
                this._coefCache.set(publicKey.x, coef);
            }
            return coef;
        }
        addTweak(tweak, xOnly) {
            let publicKey = this.publicKey;
            if (xOnly && !hasEvenY(this.publicKey)) {
                publicKey = publicKey.negate();
            }
            publicKey = Point.BASE.multiplyAndAddUnsafe(publicKey, tweak, _1n);
            if (!publicKey)
                throw new Error('Tweak failed');
            tweak = mod(this.tweak + tweak, CURVE.n);
            if (!xOnly) {
                tweak = CURVE.n - tweak;
            }
            let parityFactor = this.parityFactor;
            if (!xOnly && !hasEvenY(this.publicKey)) {
                parityFactor = !parityFactor;
            }
            if (!hasEvenY(publicKey)) {
                parityFactor = !parityFactor;
            }
            return this.copyWith(publicKey, parityFactor, tweak);
        }
        toHex() {
            return (this.publicKey.toHex(true) +
                bytesToHex(this.publicKeyHash) +
                numTo32bStr(this.secondPublicKeyX) +
                (this.parityFactor ? '01' : '00') +
                numTo32bStr(this.tweak));
        }
        static fromHex(hex) {
            const bytes = ensureBytes(hex);
            if (bytes.length !== 130)
                throw new TypeError(`MusigKeyAggCache.fromHex: expected 130 bytes, not ${bytes.length}`);
            const cache = new MusigKeyAggCache(bytes.subarray(33, 65), bytesToNumber(bytes.subarray(65, 97)), Point.fromHex(bytes.subarray(0, 33)), bytes[97] === 1, bytesToNumber(bytes.subarray(98, 130)));
            cache.assertValidity();
            return cache;
        }
        toRawBytes() {
            return hexToBytes(this.toHex());
        }
        toMusigPublicKey() {
            return {
                parity: hasEvenY(this.publicKey) ? 0 : 1,
                publicKey: this.publicKey.toRawX(),
                keyAggCache: this.toHex(),
            };
        }
    }
    class MusigProcessedNonce {
        constructor(finalNonceHasOddY, finalNonceX, coefficient, challenge, sPart) {
            this.finalNonceHasOddY = finalNonceHasOddY;
            this.finalNonceX = finalNonceX;
            this.coefficient = coefficient;
            this.challenge = challenge;
            this.sPart = sPart;
            this.assertValidity();
        }
        static fromHex(hex) {
            const bytes = ensureBytes(hex);
            if (bytes.length !== 129)
                throw new TypeError(`MusigProcessedNonce.fromHex: expected 129 bytes, not ${bytes.length}`);
            return new MusigProcessedNonce(bytes[0] === 1, bytesToNumber(bytes.subarray(1, 33)), bytesToNumber(bytes.subarray(33, 65)), bytesToNumber(bytes.subarray(65, 97)), bytesToNumber(bytes.subarray(97, 129)));
        }
        assertValidity() {
            if (!isValidFieldElement(this.finalNonceX) ||
                !isWithinCurveOrder(this.coefficient) ||
                !isWithinCurveOrder(this.challenge) ||
                (this.sPart !== _0n && !isWithinCurveOrder(this.sPart)))
                throw new Error('Invalid ProcessedNonce');
        }
        toHex() {
            return ((this.finalNonceHasOddY ? '01' : '00') +
                numTo32bStr(this.finalNonceX) +
                numTo32bStr(this.coefficient) +
                numTo32bStr(this.challenge) +
                numTo32bStr(this.sPart));
        }
        toRawBytes() {
            return hexToBytes(this.toHex());
        }
    }
    function* musigNonceGen(sessionId = utils.randomBytes(), privateKey, message, aggregatePublicKey, extraInput) {
        const messages = [];
        messages.push(ensureBytes(sessionId));
        if (privateKey)
            messages.push(normalize32b(privateKey));
        if (message)
            messages.push(ensureBytes(message));
        if (aggregatePublicKey)
            messages.push(normalize32b(aggregatePublicKey));
        if (extraInput)
            messages.push(ensureBytes(extraInput));
        const seed = yield* taggedHash(TAGS.musig_nonce, ...messages);
        const privateNonce = new Uint8Array(64);
        const publicNonce = new Uint8Array(66);
        for (let i = 0; i < 2; i++) {
            const k = yield* sha256(seed, Uint8Array.of(i));
            privateNonce.set(k, i * 32);
            publicNonce.set(Point.fromPrivateKey(k).toRawBytes(true), i * 33);
        }
        return { privateNonce, publicNonce };
    }
    function nonceAgg(nonces) {
        const noncePoints = nonces.map((nonce) => normalizeMusigPublicNonce(nonce));
        const aggNonces = noncePoints.reduce((prev, cur) => [prev[0].add(cur[0]), prev[1].add(cur[1])]);
        return concatBytes(aggNonces[0].toRawBytes(true), aggNonces[1].toRawBytes(true));
    }
    function* musigNonceProcess(aggNonce, message, cache) {
        const pubKeyX = cache.publicKey.toRawX();
        const aggNonceB = musigPublicNonceToBytes(aggNonce);
        const coefficientHash = yield* taggedHash(TAGS.musig_noncecoef, aggNonceB, pubKeyX, message);
        const coefficient = bytesToNumber(coefficientHash);
        const aggNonces = normalizeMusigPublicNonce(aggNonce);
        const finalNonce = aggNonces[0].add(aggNonces[1].multiply(coefficient));
        const finalNonceX = finalNonce.toRawX();
        const challengeHash = yield* taggedHash(TAGS.challenge, finalNonceX, pubKeyX, message);
        const challenge = mod(bytesToNumber(challengeHash), CURVE.n);
        let sPart = _0n;
        if (cache.tweak !== _0n) {
            sPart = mod(challenge * cache.tweak, CURVE.n);
        }
        return new MusigProcessedNonce(!hasEvenY(finalNonce), finalNonce.x, coefficient, challenge, sPart);
    }
    function* musigPartialVerifyInner(sig, publicKey, publicNonce, cache, processedNonce) {
        const publicNonces = normalizeMusigPublicNonce(publicNonce);
        let rj = publicNonces[0].add(publicNonces[1].multiply(processedNonce.coefficient));
        if (processedNonce.finalNonceHasOddY) {
            rj = rj.negate();
        }
        const mu = yield* cache.coefficient(publicKey);
        let e = processedNonce.challenge;
        if (!cache.parityFactor) {
            e = CURVE.n - e;
        }
        const ver = Point.BASE.multiplyAndAddUnsafe(publicKey, sig, mod(e * mu, CURVE.n));
        if (!ver)
            return false;
        return ver.equals(rj);
    }
    function* musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache) {
        let privateKey = normalizePrivateKey(privKey);
        const publicKey = Point.fromPrivateKey(privateKey);
        const cache = MusigKeyAggCache.fromHex(keyAggCache);
        const mu = yield* cache.coefficient(publicKey);
        const processedNonce = yield* musigNonceProcess(aggNonce, ensureBytes(message), cache);
        const privateNonces = normalizeMusigPrivateNonce(nonce.privateNonce);
        if (hasEvenY(publicKey) === cache.parityFactor) {
            privateKey = CURVE.n - privateKey;
        }
        privateKey = mod(privateKey * mu, CURVE.n);
        for (let i = 0; i < privateNonces.length; i++) {
            if (processedNonce.finalNonceHasOddY) {
                privateNonces[i] = CURVE.n - privateNonces[i];
            }
        }
        let sig = mod(processedNonce.challenge * privateKey, CURVE.n);
        sig = mod(sig + privateNonces[0] + privateNonces[1] * processedNonce.coefficient, CURVE.n);
        const verificationKey = normalizeEvenPublicKey(publicKey);
        const valid = yield* musigPartialVerifyInner(sig, verificationKey, nonce.publicNonce, cache, processedNonce);
        if (!valid)
            throw new Error('Partial signature failed verification');
        return { sig: numTo32b(sig), session: processedNonce.toHex() };
    }
    function* musigPartialVerify(sig, message, pubKey, publicNonce, aggNonce, keyAggCache) {
        const cache = MusigKeyAggCache.fromHex(keyAggCache);
        const processedNonce = yield* musigNonceProcess(aggNonce, ensureBytes(message), cache);
        const publicKey = normalizeEvenPublicKey(pubKey);
        const valid = yield* musigPartialVerifyInner(normalizePrivateKey(sig), publicKey, publicNonce, cache, processedNonce);
        return valid && { session: processedNonce.toHex() };
    }
    async function keyAgg(publicKeys, tweak) {
        const cache = await callAsync(MusigKeyAggCache.fromPublicKeys(publicKeys));
        if (tweak !== undefined)
            cache.addTweak(normalizePrivateKey(tweak), false);
        return cache.toMusigPublicKey();
    }
    function keyAggSync(publicKeys, tweak) {
        const cache = callSync(MusigKeyAggCache.fromPublicKeys(publicKeys));
        if (tweak !== undefined)
            cache.addTweak(normalizePrivateKey(tweak), false);
        return cache.toMusigPublicKey();
    }
    function tweak(keyAggCache, tweak, xOnly = true) {
        const cache = MusigKeyAggCache.fromHex(keyAggCache);
        cache.addTweak(normalizePrivateKey(tweak), xOnly);
        return cache.toMusigPublicKey();
    }
    function nonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput) {
        return callAsync(musigNonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput));
    }
    function nonceGenSync(sessionId, privateKey, message, aggregatePublicKey, extraInput) {
        return callSync(musigNonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput));
    }
    function partialSign(message, privKey, nonce, aggNonce, keyAggCache) {
        return callAsync(musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache));
    }
    function partialSignSync(message, privKey, nonce, aggNonce, keyAggCache) {
        return callSync(musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache));
    }
    function partialVerify(sig, message, publicKey, publicNonce, aggNonce, keyAggCache) {
        return callAsync(musigPartialVerify(sig, message, publicKey, publicNonce, aggNonce, keyAggCache));
    }
    function partialVerifySync(sig, message, publicKey, publicNonce, aggNonce, keyAggCache) {
        return callSync(musigPartialVerify(sig, message, publicKey, publicNonce, aggNonce, keyAggCache));
    }
    function signAgg(sigs, session) {
        const processedNonce = MusigProcessedNonce.fromHex(session);
        const normalizedSigs = sigs.map((sig) => normalizePrivateKey(sig));
        return concatBytes(numTo32b(processedNonce.finalNonceX), numTo32b(normalizedSigs.reduce((prev, cur) => mod(prev + cur, CURVE.n), processedNonce.sPart)));
    }
    const TAGS = {
        challenge: 'BIP0340/challenge',
        keyagg_list: 'KeyAgg list',
        keyagg_coef: 'KeyAgg coefficient',
        musig_nonce: 'MuSig/nonce',
        musig_noncecoef: 'MuSig/noncecoef',
    };
    function* taggedHash(tag, ...messages) {
        return yield { type: 'tagged', tag, messages };
    }
    function* sha256(...messages) {
        return yield { type: 'sha256', messages };
    }
    function callSync(gen) {
        let result = gen.next();
        while (!result.done) {
            throw new Error('utils.sha256Sync is undefined, you need to set it');
        }
        return result.value;
    }
    async function callAsync(gen) {
        let result = gen.next();
        while (!result.done) {
            if (result.value.type === 'tagged') {
                result = gen.next(await utils.taggedHash(result.value.tag, ...result.value.messages));
            }
            else if (result.value.type === 'sha256') {
                result = gen.next(await utils.sha256(...result.value.messages));
            }
        }
        return result.value;
    }

    exports.keyAgg = keyAgg;
    exports.keyAggSync = keyAggSync;
    exports.nonceAgg = nonceAgg;
    exports.nonceGen = nonceGen;
    exports.nonceGenSync = nonceGenSync;
    exports.partialSign = partialSign;
    exports.partialSignSync = partialSignSync;
    exports.partialVerify = partialVerify;
    exports.partialVerifySync = partialVerifySync;
    exports.signAgg = signAgg;
    exports.tweak = tweak;

    Object.defineProperty(exports, '__esModule', { value: true });

}));
