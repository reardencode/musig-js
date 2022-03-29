'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.pointCompress =
  exports.hasEvenY =
  exports.pointX =
  exports.pointNegate =
  exports.isSecret =
  exports.secretMod =
  exports.secretNegate =
  exports.secretMultiply =
  exports.secretAdd =
  exports.isXOnlyPoint =
  exports.isPoint =
    void 0;
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _5n = BigInt(5);
const _7n = BigInt(7);
const _64n = BigInt(64);
const _64mask = BigInt('0xFFFFFFFFFFFFFFFF');
const MAX_INT = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
const CURVE = {
  b: BigInt(7),
  P: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'),
  n: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
};
function read32b(bytes) {
  if (bytes.length !== 32) throw new Error(`Expected 32-bytes, not ${bytes.length}`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  let b = view.getBigUint64(0);
  for (let offs = 8; offs < bytes.length; offs += 8) {
    b <<= _64n;
    b += view.getBigUint64(offs);
  }
  return b;
}
function write32b(num) {
  if (num < _0n || num > MAX_INT) throw new Error('Expected positive 32-byte number');
  const result = new Uint8Array(32);
  const view = new DataView(result.buffer, result.byteOffset, result.length);
  for (let offs = 24; offs >= 0; offs -= 8) {
    view.setBigUint64(offs, num & _64mask);
    num >>= _64n;
  }
  return result;
}
function readSecret(bytes) {
  const a = read32b(bytes);
  if (a >= CURVE.n) throw new Error('Expected value mod n');
  return a;
}
function secp256k1Right(x) {
  const x2 = (x * x) % CURVE.P;
  const x3 = (x2 * x) % CURVE.P;
  return (x3 + CURVE.b) % CURVE.P;
}
function jacobiSymbol(a) {
  if (a === _0n) return 0;
  let p = CURVE.P;
  let sign = 1;
  for (;;) {
    let and3;
    for (and3 = a & _3n; and3 === _0n; a >>= _2n, and3 = a & _3n);
    if (and3 === _2n) {
      a >>= _1n;
      const pand7 = p & _7n;
      if (pand7 === _3n || pand7 === _5n) sign = -sign;
    }
    if (a === _1n) break;
    if ((_3n & a) === _3n && (_3n & p) === _3n) sign = -sign;
    [a, p] = [p % a, a];
  }
  return sign > 0 ? 1 : -1;
}
function isPoint(p) {
  if (p.length < 33) return false;
  const t = p[0];
  if (p.length === 33) {
    return (t === 0x02 || t === 0x03) && isXOnlyPoint(p.subarray(1));
  }
  if (t !== 0x04 || p.length !== 65) return false;
  const x = read32b(p.subarray(1, 33));
  if (x === _0n) return false;
  if (x >= CURVE.P) return false;
  const y = read32b(p.subarray(33));
  if (y === _0n) return false;
  if (y >= CURVE.P) return false;
  const left = (y * y) % CURVE.P;
  const right = secp256k1Right(x);
  return left === right;
}
exports.isPoint = isPoint;
function isXOnlyPoint(p) {
  if (p.length !== 32) return false;
  const x = read32b(p);
  if (x === _0n) return false;
  if (x >= CURVE.P) return false;
  const y2 = secp256k1Right(x);
  return jacobiSymbol(y2) === 1;
}
exports.isXOnlyPoint = isXOnlyPoint;
function secretAdd(a, b) {
  const aN = readSecret(a);
  const bN = readSecret(b);
  const sum = (aN + bN) % CURVE.n;
  return write32b(sum);
}
exports.secretAdd = secretAdd;
function secretMultiply(a, b) {
  const aN = readSecret(a);
  const bN = readSecret(b);
  const product = (aN * bN) % CURVE.n;
  return write32b(product);
}
exports.secretMultiply = secretMultiply;
function secretNegate(a) {
  const aN = readSecret(a);
  const negated = aN === _0n ? _0n : CURVE.n - aN;
  return write32b(negated);
}
exports.secretNegate = secretNegate;
function secretMod(a) {
  const aN = read32b(a);
  const remainder = aN % CURVE.n;
  return write32b(remainder);
}
exports.secretMod = secretMod;
function isSecret(s) {
  const sN = read32b(s);
  return sN < CURVE.n;
}
exports.isSecret = isSecret;
function pointNegate(p) {
  const negated = p.slice();
  if (p.length === 33) {
    negated[0] = p[0] === 2 ? 3 : 2;
  } else if (p.length === 65) {
    const y = read32b(p.subarray(33));
    if (y >= CURVE.P) throw new Error('Expected Y coordinate mod P');
    const minusY = CURVE.P - y;
    negated.set(write32b(minusY), 33);
  } else {
    throw new Error('Wrong length to be a point');
  }
  return negated;
}
exports.pointNegate = pointNegate;
function pointX(p) {
  if (p.length === 32) return p;
  if (p.length === 33 || p.length == 65) return p.slice(1, 33);
  throw new Error('Wrong length to be a point');
}
exports.pointX = pointX;
function hasEvenY(p) {
  if (p.length === 33) return p[0] % 2 === 0;
  if (p.length === 65) return p[64] % 2 === 0;
  throw new Error('Wrong length to be a point');
}
exports.hasEvenY = hasEvenY;
function pointCompress(p) {
  if (p.length === 33) return p;
  if (p.length !== 65) throw new Error('Wrong length to be a point');
  const compressed = new Uint8Array(33);
  compressed.set(p.subarray(1, 33), 1);
  compressed[0] = hasEvenY(p) ? 2 : 3;
  return compressed;
}
exports.pointCompress = pointCompress;
