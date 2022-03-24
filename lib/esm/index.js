/*! musig-js - MIT License (c) 2022 Brandon Black */
import { CURVE, Point, utils } from '@noble/secp256k1';
const _0n = BigInt(0);
const _1n = BigInt(1);
const _32n = BigInt(32);
const _64n = BigInt(64);
const _64mask = BigInt('0xffffffffffffffff');
const POW_2_256 = BigInt(2) ** BigInt(256);
function concatBytes(...arrays) {
  if (arrays.length === 1) return arrays[0];
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
const hexes = new Array(256).fill(0).map((_, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a) {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  const a = new Array(uint8a.length);
  for (let i = 0; i < uint8a.length; i++) {
    a[i] = hexes[uint8a[i]];
  }
  return a.join('');
}
function numTo32bStr(num) {
  if (num > POW_2_256) throw new Error('Expected number < 2^256');
  return num.toString(16).padStart(64, '0');
}
function numTo32b(num) {
  if (num > POW_2_256) throw new Error('Expected number < 2^256');
  let b = BigInt(num);
  const result = new Uint8Array(32);
  const view = new DataView(result.buffer);
  for (let i = 3; i >= 0; i--) {
    view.setBigUint64(i * 8, b & _64mask);
    b >>= _64n;
  }
  return result;
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
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
  const nBytes = hex.length / 2;
  const nUint32s = Math.ceil(nBytes / 4);
  const buf = new ArrayBuffer(nUint32s * 4);
  const view = new DataView(buf);
  for (let i = hex.length, j = buf.byteLength - 4; i > 0; i -= 8, j -= 4) {
    const uint32 = Number.parseInt(hex.substring(i - 8, i), 16);
    view.setUint32(j, uint32);
  }
  return new Uint8Array(buf, buf.byteLength - nBytes);
}
function bytesToNumber(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  let offs = 0;
  let i = 0;
  if (bytes.length % 2 === 1) {
    i += view.getUint8(offs);
    offs += 1;
  }
  if (bytes.length % 4 >= 2) {
    i <<= 16;
    i += view.getUint16(offs);
    offs += 2;
  }
  let b = BigInt(i);
  if (bytes.length % 8 >= 4) {
    b <<= _32n;
    b += BigInt(view.getUint32(offs));
    offs += 4;
  }
  for (; offs < bytes.length; offs += 8) {
    b <<= _64n;
    b += view.getBigUint64(offs);
  }
  return b;
}
function ensureBytes(hex) {
  return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
}
function normalizeScalar(num) {
  if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0) return BigInt(num);
  if (typeof num === 'bigint' && isWithinCurveOrder(num)) return num;
  throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
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
  } else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
    num = BigInt(key);
  } else if (typeof key === 'string') {
    if (key.length !== 64) throw new Error('Expected 32 bytes of private key');
    num = hexToNumber(key);
  } else if (isUint8a(key)) {
    if (key.length !== 32) throw new Error('Expected 32 bytes of private key');
    num = bytesToNumber(key);
  } else {
    throw new TypeError('Expected valid private key');
  }
  if (!isWithinCurveOrder(num)) throw new Error('Expected private key: 0 < key < n');
  return num;
}
function normalizePublicKey(publicKey) {
  if (publicKey instanceof Point) {
    publicKey.assertValidity();
    return publicKey;
  } else {
    return Point.fromHex(publicKey);
  }
}
function hasEvenY(point) {
  return (point.y & _1n) === _0n;
}
function normalize33b(p) {
  if (p instanceof Point) return p.toRawBytes(true);
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
  return [normalizePrivateKey(privateNonce[0]), normalizePrivateKey(privateNonce[1])];
}
function normalizeMusigPublicNonce(publicNonce) {
  if (!Array.isArray(publicNonce) || publicNonce.length !== 2) {
    const publicNonceB = ensureBytes(publicNonce);
    publicNonce = [publicNonceB.subarray(0, 33), publicNonceB.subarray(33)];
  }
  return [normalizePublicKey(publicNonce[0]), normalizePublicKey(publicNonce[1])];
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
  constructor(
    publicKeyHash,
    secondPublicKeyX,
    publicKey = Point.ZERO,
    parity = false,
    tweak = _0n,
    _coefCache = new Map()
  ) {
    this.publicKeyHash = publicKeyHash;
    this.secondPublicKeyX = secondPublicKeyX;
    this.publicKey = publicKey;
    this.parity = parity;
    this.tweak = tweak;
    this._coefCache = _coefCache;
  }
  copyWith(publicKey, parity, tweak) {
    const cache = new MusigKeyAggCache(
      this.publicKeyHash,
      this.secondPublicKeyX,
      publicKey,
      parity,
      tweak,
      this._coefCache
    );
    cache.assertValidity();
    return cache;
  }
  static *fromPublicKeys(pubKeys, sort = true) {
    if (pubKeys.length === 0) throw new Error('Cannot aggregate 0 public keys');
    const publicKeys = pubKeys.map((pk) => normalizeEvenPublicKey(pk));
    if (sort) publicKeys.sort((a, b) => (a.x > b.x ? 1 : -1));
    const secondPublicKeyIndex = publicKeys.findIndex((pk) => !publicKeys[0].equals(pk));
    const secondPublicKey =
      secondPublicKeyIndex >= 0 ? publicKeys[secondPublicKeyIndex] : Point.ZERO;
    const publicKeyHash = yield* taggedHash(
      TAGS.keyagg_list,
      ...publicKeys.map((pk) => pk.toRawX())
    );
    const cache = new MusigKeyAggCache(publicKeyHash, secondPublicKey.x);
    let publicKey = secondPublicKey;
    for (let i = 0; i < publicKeys.length; i++) {
      if (i === secondPublicKeyIndex) continue;
      const pk = publicKeys[i];
      publicKey = publicKey.multiplyAndAddUnsafe(pk, _1n, yield* cache.coefficient(pk));
      if (publicKey === undefined) throw new Error('Unexpected public key at infinity');
    }
    return cache.copyWith(publicKey);
  }
  assertValidity() {
    this.publicKey.assertValidity();
    if (
      this.publicKeyHash.length !== 32 ||
      (this.secondPublicKeyX !== _0n && !isValidFieldElement(this.secondPublicKeyX)) ||
      (this.tweak !== _0n && !isWithinCurveOrder(this.tweak))
    )
      throw new Error('Invalid KeyAggCache');
  }
  *coefficient(publicKey) {
    if (publicKey.x === this.secondPublicKeyX) return _1n;
    let coef = this._coefCache.get(publicKey.x);
    if (coef === undefined) {
      coef = bytesToNumber(
        yield* taggedHash(TAGS.keyagg_coef, this.publicKeyHash, publicKey.toRawX())
      );
      this._coefCache.set(publicKey.x, coef);
    }
    return coef;
  }
  addTweaks(tweaks, tweaksXOnly) {
    if (tweaksXOnly === undefined) tweaksXOnly = new Array(tweaks.length).fill(false);
    if (tweaks.length !== tweaksXOnly.length)
      throw new Error('tweaks and tweaksXOnly have different lengths');
    let publicKey = this.publicKey;
    let parity = this.parity;
    let tweak = this.tweak;
    for (let i = 0; i < tweaks.length; i++) {
      if (!hasEvenY(publicKey) && tweaksXOnly[i]) {
        parity = !parity;
        tweak = CURVE.n - tweak;
        publicKey = publicKey.negate();
      }
      publicKey = Point.BASE.multiplyAndAddUnsafe(publicKey, tweaks[i], _1n);
      if (!publicKey) throw new Error('Tweak failed');
      tweak = mod(tweak + tweaks[i], CURVE.n);
    }
    return this.copyWith(publicKey, parity, tweak);
  }
  toHex() {
    return (
      this.publicKey.toHex(true) +
      bytesToHex(this.publicKeyHash) +
      numTo32bStr(this.secondPublicKeyX) +
      (this.parity ? '01' : '00') +
      numTo32bStr(this.tweak)
    );
  }
  static fromHex(hex) {
    const bytes = ensureBytes(hex);
    if (bytes.length !== 130)
      throw new TypeError(`MusigKeyAggCache.fromHex: expected 130 bytes, not ${bytes.length}`);
    const cache = new MusigKeyAggCache(
      bytes.subarray(33, 65),
      bytesToNumber(bytes.subarray(65, 97)),
      Point.fromHex(bytes.subarray(0, 33)),
      bytes[97] === 0x01,
      bytesToNumber(bytes.subarray(98, 130))
    );
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
    return new MusigProcessedNonce(
      bytes[0] === 1,
      bytesToNumber(bytes.subarray(1, 33)),
      bytesToNumber(bytes.subarray(33, 65)),
      bytesToNumber(bytes.subarray(65, 97)),
      bytesToNumber(bytes.subarray(97, 129))
    );
  }
  assertValidity() {
    if (
      !isValidFieldElement(this.finalNonceX) ||
      !isWithinCurveOrder(this.coefficient) ||
      !isWithinCurveOrder(this.challenge) ||
      (this.sPart !== _0n && !isWithinCurveOrder(this.sPart))
    )
      throw new Error('Invalid ProcessedNonce');
  }
  toHex() {
    return (
      (this.finalNonceHasOddY ? '01' : '00') +
      numTo32bStr(this.finalNonceX) +
      numTo32bStr(this.coefficient) +
      numTo32bStr(this.challenge) +
      numTo32bStr(this.sPart)
    );
  }
  toRawBytes() {
    return hexToBytes(this.toHex());
  }
}
function normalizeNonceArg(p) {
  if (!p) return [Uint8Array.of(0)];
  if (p instanceof Point) p = p.x;
  if (typeof p === 'number') {
    if (Number.isSafeInteger(p)) throw new Error(`Expected integer, got ${p}`);
    p = BigInt(p);
  }
  if (typeof p === 'bigint') {
    return [Uint8Array.of(32), numTo32b(p)];
  }
  const b = ensureBytes(p);
  return [Uint8Array.of(32), b.subarray(b.length - 32)];
}
function* musigNonceGen(
  sessionId = utils.randomBytes(),
  privateKey,
  message,
  aggregatePublicKey,
  extraInput
) {
  const messages = [];
  messages.push(ensureBytes(sessionId));
  messages.push(...normalizeNonceArg(privateKey));
  messages.push(...normalizeNonceArg(message));
  messages.push(...normalizeNonceArg(aggregatePublicKey));
  messages.push(...normalizeNonceArg(extraInput));
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
export function nonceAgg(nonces) {
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
  const finalNonce = aggNonces[0].multiplyAndAddUnsafe(aggNonces[1], _1n, coefficient);
  if (finalNonce === undefined) throw new Error('Unexpected final nonce at infinity');
  const finalNonceX = finalNonce.toRawX();
  const challengeHash = yield* taggedHash(TAGS.challenge, finalNonceX, pubKeyX, message);
  const challenge = mod(bytesToNumber(challengeHash), CURVE.n);
  let sPart = _0n;
  if (cache.tweak) {
    sPart = mod(challenge * cache.tweak, CURVE.n);
    if (!hasEvenY(cache.publicKey)) {
      sPart = CURVE.n - sPart;
    }
  }
  return new MusigProcessedNonce(
    !hasEvenY(finalNonce),
    finalNonce.x,
    coefficient,
    challenge,
    sPart
  );
}
function* musigPartialVerifyInner(sig, publicKey, publicNonce, cache, processedNonce) {
  const publicNonces = normalizeMusigPublicNonce(publicNonce);
  let rj = publicNonces[0].multiplyAndAddUnsafe(publicNonces[1], _1n, processedNonce.coefficient);
  if (rj === undefined) throw new Error('Unexpected public nonce at infinity');
  if (processedNonce.finalNonceHasOddY) {
    rj = rj.negate();
  }
  if (hasEvenY(cache.publicKey) === cache.parity) {
    publicKey = publicKey.negate();
  }
  const a = yield* cache.coefficient(publicKey);
  const ver = publicKey.multiplyAndAddUnsafe(rj, mod(processedNonce.challenge * a, CURVE.n), _1n);
  if (!ver) return false;
  const sG = Point.BASE.multiply(sig);
  return ver.equals(sG);
}
function* musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache) {
  let privateKey = normalizePrivateKey(privKey);
  const cache = MusigKeyAggCache.fromHex(keyAggCache);
  const processedNonce = yield* musigNonceProcess(aggNonce, ensureBytes(message), cache);
  const privateNonces = normalizeMusigPrivateNonce(nonce.privateNonce);
  const publicNonce = nonce.publicNonce || [
    Point.fromPrivateKey(privateNonces[0]),
    Point.fromPrivateKey(privateNonces[1]),
  ];
  if (processedNonce.finalNonceHasOddY) {
    for (let i = 0; i < privateNonces.length; i++) {
      privateNonces[i] = CURVE.n - privateNonces[i];
    }
  }
  const publicKey = Point.fromPrivateKey(privateKey);
  const a = yield* cache.coefficient(publicKey);
  if ((hasEvenY(publicKey) !== cache.parity) !== hasEvenY(cache.publicKey)) {
    privateKey = CURVE.n - privateKey;
  }
  const ad = mod(privateKey * a, CURVE.n);
  const ead = mod(processedNonce.challenge * ad, CURVE.n);
  const bk2 = mod(privateNonces[1] * processedNonce.coefficient, CURVE.n);
  const sig = mod(ead + privateNonces[0] + bk2, CURVE.n);
  const verificationKey = normalizeEvenPublicKey(publicKey);
  const valid = yield* musigPartialVerifyInner(
    sig,
    verificationKey,
    publicNonce,
    cache,
    processedNonce
  );
  if (!valid) throw new Error('Partial signature failed verification');
  return { sig: numTo32b(sig), session: processedNonce.toHex() };
}
function* musigPartialVerify(sig, message, pubKey, publicNonce, aggNonce, keyAggCache, session) {
  const cache = MusigKeyAggCache.fromHex(keyAggCache);
  const processedNonce = session
    ? MusigProcessedNonce.fromHex(session)
    : yield* musigNonceProcess(aggNonce, ensureBytes(message), cache);
  const valid = yield* musigPartialVerifyInner(
    normalizePrivateKey(sig),
    normalizeEvenPublicKey(pubKey),
    publicNonce,
    cache,
    processedNonce
  );
  return valid && { session: processedNonce.toHex() };
}
export async function keyAgg(publicKeys, opts = {}) {
  let cache = await callAsync(MusigKeyAggCache.fromPublicKeys(publicKeys, opts.sort));
  if (opts.tweaks !== undefined)
    cache = cache.addTweaks(
      opts.tweaks.map((t) => normalizePrivateKey(t)),
      opts.tweaksXOnly
    );
  return cache.toMusigPublicKey();
}
export function keyAggSync(publicKeys, opts = {}) {
  let cache = callSync(MusigKeyAggCache.fromPublicKeys(publicKeys, opts.sort));
  if (opts.tweaks !== undefined)
    cache = cache.addTweaks(
      opts.tweaks.map((t) => normalizePrivateKey(t)),
      opts.tweaksXOnly
    );
  return cache.toMusigPublicKey();
}
export function addTweaks(keyAggCache, tweaks, tweaksXOnly) {
  let cache = MusigKeyAggCache.fromHex(keyAggCache);
  cache = cache.addTweaks(
    tweaks.map((t) => normalizePrivateKey(t)),
    tweaksXOnly
  );
  return cache.toMusigPublicKey();
}
export function nonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput) {
  return callAsync(musigNonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput));
}
export function nonceGenSync(sessionId, privateKey, message, aggregatePublicKey, extraInput) {
  return callSync(musigNonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput));
}
export function partialSign(message, privKey, nonce, aggNonce, keyAggCache) {
  return callAsync(musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache));
}
export function partialSignSync(message, privKey, nonce, aggNonce, keyAggCache) {
  return callSync(musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache));
}
export function partialVerify(
  sig,
  message,
  publicKey,
  publicNonce,
  aggNonce,
  keyAggCache,
  session
) {
  return callAsync(
    musigPartialVerify(sig, message, publicKey, publicNonce, aggNonce, keyAggCache, session)
  );
}
export function partialVerifySync(
  sig,
  message,
  publicKey,
  publicNonce,
  aggNonce,
  keyAggCache,
  session
) {
  return callSync(
    musigPartialVerify(sig, message, publicKey, publicNonce, aggNonce, keyAggCache, session)
  );
}
export function signAgg(sigs, session) {
  const processedNonce = MusigProcessedNonce.fromHex(session);
  const normalizedSigs = sigs.map((sig) => normalizePrivateKey(sig));
  return concatBytes(
    numTo32b(processedNonce.finalNonceX),
    numTo32b(normalizedSigs.reduce((prev, cur) => mod(prev + cur, CURVE.n), processedNonce.sPart))
  );
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
    if (typeof utils.sha256Sync !== 'function')
      throw new Error('utils.sha256Sync is undefined, you need to set it');
    if (result.value.type === 'tagged') {
      result = gen.next(utils.taggedHashSync(result.value.tag, ...result.value.messages));
    } else if (result.value.type === 'sha256') {
      result = gen.next(utils.sha256Sync(...result.value.messages));
    }
  }
  return result.value;
}
async function callAsync(gen) {
  let result = gen.next();
  while (!result.done) {
    if (result.value.type === 'tagged') {
      result = gen.next(await utils.taggedHash(result.value.tag, ...result.value.messages));
    } else if (result.value.type === 'sha256') {
      result = gen.next(await utils.sha256(...result.value.messages));
    }
  }
  return result.value;
}
