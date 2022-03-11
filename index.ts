/*! musig-js - MIT License (c) 2022 Brandon Black */
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki
import { CURVE, Point, utils } from '@noble/secp256k1';

// Begin shamelessly copied from noble-secp256k1 by Paul Miller (https://paulmillr.com)

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);

const POW_2_256 = BigInt(2) ** BigInt(256);

// We accept hex strings besides Uint8Array for simplicity
type Hex = Uint8Array | string;
// Very few implementations accept numbers, we do it to ease learning curve
type PrivKey = Hex | bigint | number;
// 33/65-byte ECDSA key, or 32-byte Schnorr key - not interchangeable
type PubKey = Hex | Point;

// Concatenates several Uint8Arrays into one.
// TODO: check if we're copying data instead of moving it and if that's ok
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
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

// Convert between types
// ---------------------

// We can't do `instanceof Uint8Array` because it's unreliable between Web Workers etc
function isUint8a(bytes: Uint8Array | unknown): bytes is Uint8Array {
  return bytes instanceof Uint8Array;
}

const hexes = new Array(256).fill(0).map((_, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a: Uint8Array): string {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  // pre-caching improves the speed 6x
  const a = new Array(uint8a.length); // 40% faster vs progressive string concatenation
  for (let i = 0; i < uint8a.length; i++) {
    a[i] = hexes[uint8a[i]];
  }
  return a.join('');
}

function numTo32bStr(num: number | bigint): string {
  if (num > POW_2_256) throw new Error('Expected number < 2^256');
  return num.toString(16).padStart(64, '0');
}

function numTo32b(num: bigint): Uint8Array {
  return hexToBytes(numTo32bStr(num));
}

function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
  }
  // Big Endian
  return BigInt(`0x${hex}`);
}

// Caching slows it down 2-3x
function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

// Big Endian
function bytesToNumber(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

function ensureBytes(hex: Hex): Uint8Array {
  // Uint8Array.from() instead of hash.slice() because node.js Buffer
  // is instance of Uint8Array, and its slice() creates **mutable** copy
  return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
}

function normalizeScalar(num: number | bigint): bigint {
  if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0) return BigInt(num);
  if (typeof num === 'bigint' && isWithinCurveOrder(num)) return num;
  throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
}

// -------------------------

// Calculates a modulo b
function mod(a: bigint, b: bigint = CURVE.P): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}

function isWithinCurveOrder(num: bigint): boolean {
  return _0n < num && num < CURVE.n;
}

function isValidFieldElement(num: bigint): boolean {
  return _0n < num && num < CURVE.P;
}

function normalizePrivateKey(key: PrivKey): bigint {
  let num: bigint;
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

/**
 * Normalizes hex, bytes, Point to Point. Checks for curve equation.
 */
function normalizePublicKey(publicKey: PubKey): Point {
  if (publicKey instanceof Point) {
    publicKey.assertValidity();
    return publicKey;
  } else {
    return Point.fromHex(publicKey);
  }
}

function hasEvenY(point: Point): boolean {
  return (point.y & _1n) === _0n;
}

// End shamelessly copied from noble-secp256k1 by Paul Miller (https://paulmillr.com)

type MusigPrivateNonce = Hex | [PrivKey, PrivKey];
type MusigPublicNonce = Hex | [PubKey, PubKey];

interface MusigNonce {
  privateNonce: MusigPrivateNonce;
  publicNonce?: MusigPublicNonce;
}

export type MusigPublicKey = {
  parity: 0 | 1;
  publicKey: Uint8Array;
  keyAggCache: string;
};

function normalize33b(p: PubKey): Uint8Array {
  if (p instanceof Point) return p.toRawBytes(true);
  return ensureBytes(p);
}

function normalizeEvenPublicKey(pubKey: PubKey): Point {
  const publicKey = normalizePublicKey(pubKey);
  return hasEvenY(publicKey) ? publicKey : publicKey.negate();
}

function normalizeMusigPrivateNonce(privateNonce: MusigPrivateNonce): [bigint, bigint] {
  if (!Array.isArray(privateNonce) || privateNonce.length !== 2) {
    const privateNonceB = ensureBytes(privateNonce);
    privateNonce = [privateNonceB.subarray(0, 32), privateNonceB.subarray(32)];
  }
  return [normalizePrivateKey(privateNonce[0]), normalizePrivateKey(privateNonce[1])];
}

function normalizeMusigPublicNonce(publicNonce: MusigPublicNonce): [Point, Point] {
  if (!Array.isArray(publicNonce) || publicNonce.length !== 2) {
    const publicNonceB = ensureBytes(publicNonce);
    publicNonce = [publicNonceB.subarray(0, 33), publicNonceB.subarray(33)];
  }
  return [normalizePublicKey(publicNonce[0]), normalizePublicKey(publicNonce[1])];
}

function musigPublicNonceToBytes(publicNonce: MusigPublicNonce): Uint8Array {
  if (Array.isArray(publicNonce) && publicNonce.length === 2) {
    const publicNonceBytes = new Uint8Array(publicNonce.length * 33);
    for (let i = 0; i < publicNonce.length; i++) {
      publicNonceBytes.set(normalize33b(publicNonce[i]), i * 33);
    }
    return publicNonceBytes;
  }
  return ensureBytes(publicNonce);
}

// MuSig2 per
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki
// Roughly based on the secp256k1-zkp implementation

// Information needed to partially sign for an aggregate public key
class MusigKeyAggCache {
  private constructor(
    readonly publicKeyHash: Uint8Array, // L, to determine key aggregation coefficients when signing
    // If > 1 unique X-values in the key, keys with Xs identical to 2nd unique X use coffecient = 1
    readonly secondPublicKeyX: bigint,
    readonly publicKey: Point = Point.ZERO, // Current aggregate public key
    readonly parity: boolean = true,
    readonly tweak: bigint = _0n,
    private readonly _coefCache = new Map<bigint, bigint>()
  ) {}
  private copyWith(publicKey: Point, parity: boolean, tweak?: bigint): MusigKeyAggCache {
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

  static *fromPublicKeys(pubKeys: PubKey[], sort = true): U8AGenerator<MusigKeyAggCache> {
    if (pubKeys.length === 0) throw new Error('Cannot aggregate 0 public keys');
    const publicKeys = pubKeys.map((pk) => normalizeEvenPublicKey(pk));
    if (sort) publicKeys.sort((a, b) => (a.x > b.x ? 1 : -1)); // Equivalent to lexicographically sorting the hex
    const secondPublicKeyIndex = publicKeys.findIndex((pk) => !publicKeys[0].equals(pk));
    const secondPublicKey =
      secondPublicKeyIndex >= 0 ? publicKeys[secondPublicKeyIndex] : Point.ZERO;

    const publicKeyHash = yield* taggedHash(
      TAGS.keyagg_list,
      ...publicKeys.map((pk) => pk.toRawX())
    );

    const cache = new MusigKeyAggCache(publicKeyHash, secondPublicKey.x);

    let publicKey: Point | undefined = secondPublicKey;
    for (let i = 0; i < publicKeys.length; i++) {
      if (i === secondPublicKeyIndex) continue;
      const pk = publicKeys[i];
      publicKey = publicKey.multiplyAndAddUnsafe(pk, _1n, yield* cache.coefficient(pk));
      if (publicKey === undefined) throw new Error('Unexpected public key at infinity');
    }
    return cache.copyWith(publicKey, !hasEvenY(publicKey));
  }

  assertValidity(): void {
    this.publicKey.assertValidity();
    if (
      this.publicKeyHash.length !== 32 ||
      (this.secondPublicKeyX !== _0n && !isValidFieldElement(this.secondPublicKeyX)) ||
      (this.tweak !== _0n && !isWithinCurveOrder(this.tweak))
    )
      throw new Error('Invalid KeyAggCache');
  }

  *coefficient(publicKey: Point): U8AGenerator<bigint> {
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

  addTweak(tweak: bigint, xOnly = false): MusigKeyAggCache {
    let publicKey: Point | undefined = this.publicKey;
    if (xOnly && !hasEvenY(this.publicKey)) {
      publicKey = this.publicKey.negate();
    }
    publicKey = Point.BASE.multiplyAndAddUnsafe(publicKey, tweak, _1n);
    if (!publicKey) throw new Error('Tweak failed');

    let parity = this.parity;
    if (xOnly || hasEvenY(this.publicKey)) {
      tweak = mod(this.tweak + tweak, CURVE.n);
    } else {
      parity = !parity;
      tweak = mod(CURVE.n - this.tweak + tweak, CURVE.n);
    }

    if (!hasEvenY(publicKey)) {
      parity = !parity;
      tweak = CURVE.n - tweak;
    }

    return this.copyWith(publicKey, parity, tweak);
  }

  toHex(): string {
    return (
      this.publicKey.toHex(true) +
      bytesToHex(this.publicKeyHash) +
      numTo32bStr(this.secondPublicKeyX) +
      (this.parity ? '01' : '00') +
      numTo32bStr(this.tweak)
    );
  }
  static fromHex(hex: Hex): MusigKeyAggCache {
    // 33+32+32+1+32
    const bytes = ensureBytes(hex);
    if (bytes.length !== 130)
      throw new TypeError(`MusigKeyAggCache.fromHex: expected 130 bytes, not ${bytes.length}`);
    const cache = new MusigKeyAggCache(
      bytes.subarray(33, 65),
      bytesToNumber(bytes.subarray(65, 97)),
      Point.fromHex(bytes.subarray(0, 33)),
      bytes[97] === 1,
      bytesToNumber(bytes.subarray(98, 130))
    );
    cache.assertValidity();
    return cache;
  }
  toRawBytes(): Uint8Array {
    return hexToBytes(this.toHex());
  }
  toMusigPublicKey(): MusigPublicKey {
    return {
      parity: hasEvenY(this.publicKey) ? 0 : 1,
      publicKey: this.publicKey.toRawX(),
      keyAggCache: this.toHex(),
    };
  }
}

export interface MusigPartialSig {
  sig: PrivKey;
  session: Hex;
}

class MusigProcessedNonce {
  constructor(
    readonly finalNonceHasOddY: boolean,
    readonly finalNonceX: bigint,
    readonly coefficient: bigint,
    readonly challenge: bigint,
    readonly sPart: bigint
  ) {
    this.assertValidity();
  }
  static fromHex(hex: Hex): MusigProcessedNonce {
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
  assertValidity(): void {
    if (
      !isValidFieldElement(this.finalNonceX) ||
      !isWithinCurveOrder(this.coefficient) ||
      !isWithinCurveOrder(this.challenge) ||
      (this.sPart !== _0n && !isWithinCurveOrder(this.sPart))
    )
      throw new Error('Invalid ProcessedNonce');
  }
  toHex(): string {
    return (
      (this.finalNonceHasOddY ? '01' : '00') +
      numTo32bStr(this.finalNonceX) +
      numTo32bStr(this.coefficient) +
      numTo32bStr(this.challenge) +
      numTo32bStr(this.sPart)
    );
  }
  toRawBytes(): Uint8Array {
    return hexToBytes(this.toHex());
  }
}

// See https://github.com/ElementsProject/secp256k1-zkp/blob/8fd97d8/include/secp256k1_musig.h#L326
// TODO: Should we do more to prevent nonce reuse?
function normalizeNonceArg(p?: PrivKey | PubKey): [Uint8Array] | [Uint8Array, Uint8Array] {
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
  sessionId: Hex = utils.randomBytes(),
  privateKey?: PrivKey,
  message?: Hex,
  aggregatePublicKey?: PubKey,
  extraInput?: Hex
): U8AGenerator<{ privateNonce: Uint8Array; publicNonce: Uint8Array }> {
  const messages: Uint8Array[] = [];
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

export function nonceAgg(nonces: MusigPublicNonce[]): Uint8Array {
  const noncePoints = nonces.map((nonce) => normalizeMusigPublicNonce(nonce));
  const aggNonces = noncePoints.reduce((prev, cur) => [prev[0].add(cur[0]), prev[1].add(cur[1])]);
  return concatBytes(aggNonces[0].toRawBytes(true), aggNonces[1].toRawBytes(true));
}

function* musigNonceProcess(
  aggNonce: MusigPublicNonce,
  message: Uint8Array,
  cache: MusigKeyAggCache
): U8AGenerator<MusigProcessedNonce> {
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
  if (cache.tweak !== _0n) {
    sPart = mod(challenge * cache.tweak, CURVE.n);
  }

  return new MusigProcessedNonce(
    !hasEvenY(finalNonce),
    finalNonce.x,
    coefficient,
    challenge,
    sPart
  );
}

function* musigPartialVerifyInner(
  sig: bigint,
  publicKey: Point,
  publicNonce: MusigPublicNonce,
  cache: MusigKeyAggCache,
  processedNonce: MusigProcessedNonce
): U8AGenerator<boolean> {
  const publicNonces = normalizeMusigPublicNonce(publicNonce);

  let rj = publicNonces[0].multiplyAndAddUnsafe(publicNonces[1], _1n, processedNonce.coefficient);
  if (rj === undefined) throw new Error('Unexpected public nonce at infinity');
  if (processedNonce.finalNonceHasOddY) {
    rj = rj.negate();
  }
  const mu = yield* cache.coefficient(publicKey);
  let e = processedNonce.challenge;
  // This condition is inverted from secp256k1-zkp's version to facilitate .equals comparison
  if (!cache.parity) {
    e = CURVE.n - e; // Negate any of e, mu, publicKey.
  }

  const ver = Point.BASE.multiplyAndAddUnsafe(publicKey, sig, mod(e * mu, CURVE.n));
  if (!ver) return false;
  return ver.equals(rj);
}

function* musigPartialSign(
  message: Hex,
  privKey: PrivKey,
  nonce: MusigNonce,
  aggNonce: MusigPublicNonce,
  keyAggCache: Hex
): U8AGenerator<{ sig: Uint8Array; session: string }> {
  let privateKey = normalizePrivateKey(privKey);
  const publicKey = Point.fromPrivateKey(privateKey);

  const cache = MusigKeyAggCache.fromHex(keyAggCache);
  const mu = yield* cache.coefficient(publicKey);
  const processedNonce = yield* musigNonceProcess(aggNonce, ensureBytes(message), cache);
  const privateNonces = normalizeMusigPrivateNonce(nonce.privateNonce);
  // Do this before we modify the private nonces below.
  const publicNonce = nonce.publicNonce || [
    Point.fromPrivateKey(privateNonces[0]),
    Point.fromPrivateKey(privateNonces[1]),
  ];

  if (hasEvenY(publicKey) === cache.parity) {
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

function* musigPartialVerify(
  sig: PrivKey,
  message: Hex,
  pubKey: PubKey,
  publicNonce: MusigPublicNonce,
  aggNonce: MusigPublicNonce,
  keyAggCache: Hex
): U8AGenerator<false | { session: string }> {
  const cache = MusigKeyAggCache.fromHex(keyAggCache);
  const processedNonce = yield* musigNonceProcess(aggNonce, ensureBytes(message), cache);

  const valid = yield* musigPartialVerifyInner(
    normalizePrivateKey(sig),
    normalizeEvenPublicKey(pubKey),
    publicNonce,
    cache,
    processedNonce
  );
  return valid && { session: processedNonce.toHex() };
}

// X-only keys in
export async function keyAgg(
  publicKeys: PubKey[],
  opts: {
    tweak?: PrivKey;
    xOnlyTweak?: boolean;
    sort?: boolean;
  } = {}
): Promise<MusigPublicKey> {
  let cache = await callAsync(MusigKeyAggCache.fromPublicKeys(publicKeys, opts.sort));
  if (opts.tweak !== undefined)
    cache = cache.addTweak(normalizePrivateKey(opts.tweak), opts.xOnlyTweak);
  return cache.toMusigPublicKey();
}
export function keyAggSync(
  publicKeys: PubKey[],
  opts: {
    tweak?: PrivKey;
    xOnlyTweak?: boolean;
    sort?: boolean;
  } = {}
): MusigPublicKey {
  let cache = callSync(MusigKeyAggCache.fromPublicKeys(publicKeys, opts.sort));
  if (opts.tweak !== undefined)
    cache = cache.addTweak(normalizePrivateKey(opts.tweak), opts.xOnlyTweak);
  return cache.toMusigPublicKey();
}

export function addTweak(keyAggCache: Hex, tweak: PrivKey, xOnlyTweak?: boolean): MusigPublicKey {
  let cache = MusigKeyAggCache.fromHex(keyAggCache);
  cache = cache.addTweak(normalizePrivateKey(tweak), xOnlyTweak);
  return cache.toMusigPublicKey();
}

export function nonceGen(
  sessionId?: Hex,
  privateKey?: PrivKey,
  message?: Hex,
  aggregatePublicKey?: PubKey,
  extraInput?: Hex
): Promise<{ privateNonce: Uint8Array; publicNonce: Uint8Array }> {
  return callAsync(musigNonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput));
}

export function nonceGenSync(
  sessionId?: Hex,
  privateKey?: PrivKey,
  message?: Hex,
  aggregatePublicKey?: PubKey,
  extraInput?: Hex
): { privateNonce: Uint8Array; publicNonce: Uint8Array } {
  return callSync(musigNonceGen(sessionId, privateKey, message, aggregatePublicKey, extraInput));
}

export function partialSign(
  message: Hex,
  privKey: PrivKey,
  nonce: MusigNonce,
  aggNonce: MusigPublicNonce,
  keyAggCache: Hex
): Promise<{ sig: Uint8Array; session: string }> {
  return callAsync(musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache));
}

export function partialSignSync(
  message: Hex,
  privKey: PrivKey,
  nonce: MusigNonce,
  aggNonce: MusigPublicNonce,
  keyAggCache: Hex
): { sig: Uint8Array; session: string } {
  return callSync(musigPartialSign(message, privKey, nonce, aggNonce, keyAggCache));
}

export function partialVerify(
  sig: PrivKey,
  message: Hex,
  publicKey: PubKey,
  publicNonce: MusigPublicNonce,
  aggNonce: MusigPublicNonce,
  keyAggCache: Hex
): Promise<false | { session: string }> {
  return callAsync(musigPartialVerify(sig, message, publicKey, publicNonce, aggNonce, keyAggCache));
}

export function partialVerifySync(
  sig: PrivKey,
  message: Hex,
  publicKey: PubKey,
  publicNonce: MusigPublicNonce,
  aggNonce: MusigPublicNonce,
  keyAggCache: Hex
): false | { session: string } {
  return callSync(musigPartialVerify(sig, message, publicKey, publicNonce, aggNonce, keyAggCache));
}

export function signAgg(sigs: PrivKey[], session: Hex): Uint8Array {
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
} as const;

type TaggedHashArgs = { type: 'tagged'; tag: string; messages: Uint8Array[] };
type Sha256Args = { type: 'sha256'; messages: Uint8Array[] };
type U8AGeneratorArgs = TaggedHashArgs | Sha256Args;
type U8AGenerator<Ret> = Generator<U8AGeneratorArgs, Ret, Uint8Array>;

function* taggedHash(tag: string, ...messages: Uint8Array[]): U8AGenerator<Uint8Array> {
  return yield { type: 'tagged', tag, messages };
}

function* sha256(...messages: Uint8Array[]): U8AGenerator<Uint8Array> {
  return yield { type: 'sha256', messages };
}

function callSync<Ret>(gen: U8AGenerator<Ret>): Ret {
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

async function callAsync<Ret>(gen: U8AGenerator<Ret>): Promise<Ret> {
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
