/*! musig-js - MIT License (c) 2022 Brandon Black */
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki
import { Buffer as NBuffer } from 'buffer';

const TAGS = {
  challenge: 'BIP0340/challenge',
  keyagg_list: 'KeyAgg list',
  keyagg_coef: 'KeyAgg coefficient',
  musig_nonce: 'MuSig/nonce',
  musig_noncecoef: 'MuSig/noncecoef',
} as const;

interface MuSig {
  // X-only keys in
  keyAgg(
    publicKeys: Uint8Array[],
    opts: {
      tweaks?: Uint8Array[];
      tweaksXOnly?: boolean[];
      sort?: boolean;
    }
  ): AggregatePublicKey;

  addTweaks(
    keyAggSession: KeyAggSession,
    tweaks: Uint8Array[],
    tweaksXOnly?: boolean[]
  ): AggregatePublicKey;

  nonceGen({
    sessionId,
    secretKey,
    message,
    aggregatePublicKey,
    extraInput,
  }: {
    sessionId: Uint8Array;
    secretKey?: Uint8Array;
    message?: Uint8Array;
    aggregatePublicKey?: Uint8Array;
    extraInput?: Uint8Array;
  }): { secretNonce: Uint8Array; publicNonce: Uint8Array };

  nonceAgg(nonces: Uint8Array[]): Uint8Array;

  partialSign({
    message,
    secretKey,
    nonce,
    aggNonce,
    session,
  }: {
    message: Uint8Array;
    secretKey: Uint8Array;
    nonce: Nonce;
    aggNonce: Uint8Array;
    session: KeyAggSession;
  }): { sig: Uint8Array; session: Uint8Array };

  partialVerify({
    sig,
    message,
    publicKey,
    publicNonce,
    aggNonce,
    keyAggSession,
    session,
  }: {
    sig: Uint8Array;
    message: Uint8Array;
    publicKey: Uint8Array;
    publicNonce: Uint8Array;
    aggNonce: Uint8Array;
    keyAggSession: KeyAggSession;
    session?: Uint8Array;
  }): false | { session: Uint8Array };

  signAgg(sigs: Uint8Array[], session: Uint8Array): Uint8Array;
}

interface Crypto {
  /**
   * Adds a tweak to a point.
   *
   * @param p A point, compressed or uncompressed
   * @param t A tweak, 0 < t < n
   * @param compressed Whether the resulting point should be compressed.
   * @returns The tweaked point, compressed or uncompressed.
   */
  pointAddTweak(p: Uint8Array, t: Uint8Array, compressed?: boolean): Uint8Array;

  /**
   * Adds two points.
   *
   * @param a An addend point, compressed or uncompressed
   * @param b An addend point, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The sum point, compressed or uncompressed.
   */
  pointAdd(a: Uint8Array, b: Uint8Array, compressed?: boolean): Uint8Array;

  /**
   * Multiplies a point by a scalar.
   *
   * @param p A point multiplicand, compressed or uncompressed
   * @param a The multiplier, 0 < a < n
   * @param compressed Whether the resulting point should be compressed.
   * @returns The product point, compressed or uncompressed.
   */
  pointMultiply(p: Uint8Array, a: Uint8Array, compressed?: boolean): Uint8Array;

  /**
   * Negates a point, ie. returns the point with the opposite parity.
   *
   * @param p A point to negate, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The negated point, compressed or uncompressed.
   */
  pointNegate(p: Uint8Array, compressed?: boolean): Uint8Array;

  /**
   * Negates a point, ie. returns the point with the opposite parity.
   *
   * @param p A point format, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The point, compressed or uncompressed.
   */
  pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;

  /**
   * Adds one value to another, mod n.
   *
   * @param a An addend, 0 < a < n
   * @param b An addend, 0 < b < n
   * @returns The sum, 0 < sum < n
   */
  secretAdd(a: Uint8Array, b: Uint8Array): Uint8Array;

  /**
   * Multiply one value by another, mod n.
   *
   * @param a The multiplicand, 0 < a < n
   * @param b The multiplier, 0 < b < n
   * @returns The product, 0 < product < n
   */
  secretMultiply(a: Uint8Array, b: Uint8Array): Uint8Array;

  /**
   * Negates a value, mod n.
   *
   * @param a The value to negate, 0 < a < n
   * @returns The negated value, 0 < negated < n
   */
  secretNegate(a: Uint8Array): Uint8Array;

  /**
   * @param a The value to reduce
   * @returns a mod n
   */
  secretMod(a: Uint8Array): Uint8Array;

  /**
   * @param s A buffer to check against the curve order
   * @returns true if s is a 32-byte array 0 < s < n
   */
  isSecret(s: Uint8Array): boolean;

  /**
   * @param p A buffer to check against the curve equation, compressed or
   * uncompressed.
   * @returns true if p is a valid point on secp256k1, false otherwise
   */
  isPoint(p: Uint8Array): boolean;

  /**
   * @param p A buffer to check against the curve equation.
   * @returns true if p is the x coordinate of a valid point on secp256k1,
   * false otherwise
   */
  isXOnlyPoint(p: Uint8Array): boolean;

  /**
   * @param p an x coordinate
   * @returns the xy, uncompressed point if p is on the curve, otherwise null.
   */
  liftX(p: Uint8Array): Uint8Array | null;

  /**
   * Gets a public key for secret key.
   *
   * @param s Secret key
   * @param compressed Whether the resulting point should be compressed.
   * @returns The public key, compressed or uncompressed
   */
  getPublicKey(s: Uint8Array, compressed?: boolean): Uint8Array;

  /**
   * Performs a BIP340-style tagged hash.
   *
   * @param tag
   * @param messages Array of data to hash.
   * @return The 32-byte BIP340-style tagged hash.
   */
  taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array;

  /**
   * SHA256 hash.
   *
   * @param messages Array of data to hash.
   * @return The 32-byte SHA256 digest.
   */
  sha256(...messages: Uint8Array[]): Uint8Array;
}

const U8A0 = NBuffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);
const U8A1 = NBuffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);

/**
 * @param p x-only, compressed or uncompressed
 * @returns the x coordinate of p
 */
function pointX(p: Uint8Array): Uint8Array {
  if (p.length === 32) return p;
  if (p.length === 33) return p.subarray(1);
  if (p.length === 65) return p.subarray(1, 33);
  throw new Error('Wrong length to be a point');
}

/**
 * @param p a point, compressed or uncompressed
 * @returns true if p has an even y coordinate, false otherwise
 */
function hasEvenY(p: Uint8Array): boolean {
  if (p.length === 33) return p[0] % 2 === 0;
  if (p.length === 65) return p[32] % 2 === 0;
  throw new Error('Wrong length to be a point');
}

/**
 * Compares two Uint8Arrays in byte order.
 * @returns < 0, 0, > 0 if a is < b, === b or > b respectively
 */
function compare32b(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== 32 || b.length !== 32) throw new Error('Can only compare 32 byte arrays');
  const aD = new DataView(a.buffer);
  const bD = new DataView(b.buffer);
  for (let i = 0; i < 8; i++) {
    const cmp = aD.getUint32(i * 4) - bD.getUint32(i * 4);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

export interface Nonce {
  secretNonce: Uint8Array; // 64 bytes
  publicNonce?: Uint8Array; // 66 bytes
}

export interface KeyAggSession {
  base: Uint8Array; // 32 bytes
  rest: Uint8Array; // 98 bytes
}

export interface AggregatePublicKey {
  parity: 0 | 1;
  publicKey: Uint8Array; // 32 bytes
  session: KeyAggSession;
}

export interface MuSigPartialSig {
  sig: Uint8Array;
  session: Uint8Array;
}

// MuSig2 per
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki
// Roughly based on the secp256k1-zkp implementation
export function MuSigFactory(ecc: Crypto): MuSig {
  // Caches coefficients associated with a specific publicKeyHash
  const _coefCache = new WeakMap<Uint8Array, Map<string, Uint8Array>>();

  // Information needed to partially sign for an aggregate public key
  class KeyAggCache {
    private constructor(
      readonly publicKeyHash: Uint8Array, // L, to determine key aggregation coefficients when signing
      // If > 1 unique X-values in the key, keys with Xs identical to 2nd unique X use coffecient = 1
      readonly secondPublicKeyX: Uint8Array = U8A0,
      readonly publicKey: Uint8Array = new Uint8Array(65), // Current xy aggregate public key
      readonly parity: boolean = false,
      readonly tweak: Uint8Array = U8A0,
      private readonly _coefCache = new Map<string, Uint8Array>()
    ) {}
    private copyWith(publicKey: Uint8Array, parity?: boolean, tweak?: Uint8Array): KeyAggCache {
      const cache = new KeyAggCache(
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

    static fromPublicKeys(publicKeys: Uint8Array[], sort = true): KeyAggCache {
      if (publicKeys.length === 0) throw new Error('Cannot aggregate 0 public keys');
      if (sort) publicKeys.sort((a, b) => compare32b(a, b));
      const evenPublicKeys = publicKeys.map((pk) => {
        const evenPublicKey = ecc.liftX(pk);
        if (!evenPublicKey) throw new Error('Invalid public key');
        return evenPublicKey;
      });
      const secondPublicKey = publicKeys.slice(1).find((pk) => compare32b(publicKeys[0], pk) !== 0);

      const publicKeyHash = ecc.taggedHash(TAGS.keyagg_list, ...publicKeys);

      const cache = new KeyAggCache(publicKeyHash, secondPublicKey);

      const shiftedPublicKeys = publicKeys.map((pk, i) => {
        const coef = cache.coefficient(pk);
        if (coef === U8A1) return evenPublicKeys[i];
        return ecc.pointMultiply(evenPublicKeys[i], coef);
      });

      const publicKey = shiftedPublicKeys.reduce((a, b) => ecc.pointAdd(a, b));
      return cache.copyWith(publicKey);
    }

    assertValidity(): void {
      if (
        !ecc.isPoint(this.publicKey) ||
        this.publicKeyHash.length !== 32 ||
        (compare32b(this.secondPublicKeyX, U8A0) !== 0 &&
          !ecc.isXOnlyPoint(this.secondPublicKeyX)) ||
        (this.tweak !== U8A0 && !ecc.isSecret(this.tweak))
      )
        throw new Error('Invalid KeyAggCache');
    }

    coefficient(publicKey: Uint8Array): Uint8Array {
      if (compare32b(publicKey, this.secondPublicKeyX) === 0) return U8A1;
      const key = Buffer.from(publicKey).toString('hex');
      let coef = this._coefCache.get(key);
      if (coef === undefined) {
        coef = ecc.taggedHash(TAGS.keyagg_coef, this.publicKeyHash, publicKey);
        this._coefCache.set(key, coef);
      }
      return coef;
    }

    addTweaks(tweaks: Uint8Array[], tweaksXOnly?: boolean[]): KeyAggCache {
      if (tweaksXOnly === undefined) tweaksXOnly = new Array(tweaks.length).fill(false);
      if (tweaks.length !== tweaksXOnly.length)
        throw new Error('tweaks and tweaksXOnly have different lengths');
      let publicKey: Uint8Array | undefined = this.publicKey;
      let parity = this.parity;
      let tweak = this.tweak;

      for (let i = 0; i < tweaks.length; i++) {
        if (!hasEvenY(publicKey) && tweaksXOnly[i]) {
          parity = !parity;
          tweak = ecc.secretNegate(tweak);
          publicKey = ecc.pointNegate(publicKey); // -1 * Q[v-1]
        }
        publicKey = ecc.pointAddTweak(publicKey, tweaks[i]); // +/-Q + tG
        if (!publicKey) throw new Error('Tweak failed');
        tweak = ecc.secretAdd(tweak, tweaks[i]);
      }

      return this.copyWith(publicKey, parity, tweak);
    }

    dump(): KeyAggSession {
      return {
        base: this.publicKeyHash,
        rest: NBuffer.concat([
          this.secondPublicKeyX,
          this.publicKey,
          Uint8Array.of(this.parity ? 1 : 0),
          this.tweak,
        ]),
      };
    }
    static load(session: KeyAggSession): KeyAggCache {
      // 32, and 65+32+1+32
      if (session.base.length !== 32 || session.rest.length !== 130)
        throw new TypeError(
          `expected 32 + 130 bytes, not ${session.base.length} + ${session.rest.length}`
        );
      const cache = new KeyAggCache(
        session.base,
        session.rest.slice(0, 65),
        session.rest.slice(65, 97),
        session.rest[97] === 0x01,
        session.rest.slice(98, 130),
        _coefCache.get(session.base)
      );
      cache.assertValidity();
      return cache;
    }
    toAggregatePublicKey(): AggregatePublicKey {
      return {
        parity: hasEvenY(this.publicKey) ? 0 : 1,
        publicKey: pointX(this.publicKey),
        session: this.dump(),
      };
    }
  }

  class ProcessedNonce {
    constructor(
      readonly finalNonceHasOddY: boolean,
      readonly finalNonceX: Uint8Array,
      readonly coefficient: Uint8Array,
      readonly challenge: Uint8Array,
      readonly sPart: Uint8Array
    ) {
      this.assertValidity();
    }
    static load(session: Uint8Array): ProcessedNonce {
      if (session.length !== 129)
        throw new TypeError(`expected 97 or 129 bytes, not ${session.length}`);
      return new ProcessedNonce(
        session[0] === 1,
        session.slice(1, 33),
        session.slice(33, 65),
        session.slice(65, 97),
        session.slice(97)
      );
    }
    assertValidity(): void {
      if (
        !ecc.isXOnlyPoint(this.finalNonceX) ||
        !ecc.isSecret(this.coefficient) ||
        !ecc.isSecret(this.challenge) ||
        (compare32b(U8A0, this.sPart) !== 0 && !ecc.isSecret(this.sPart))
      )
        throw new Error('Invalid ProcessedNonce');
    }
    dump(): Uint8Array {
      return NBuffer.concat([
        Uint8Array.of(this.finalNonceHasOddY ? 1 : 0),
        this.finalNonceX,
        this.coefficient,
        this.challenge,
        this.sPart,
      ]);
    }
  }

  function normalizeNonceArg(p?: Uint8Array): [Uint8Array] | [Uint8Array, Uint8Array] {
    if (!p) return [Uint8Array.of(0)];
    if (p.length !== 32) throw new Error('Expected 32 bytes');
    return [Uint8Array.of(32), p];
  }

  // See https://github.com/ElementsProject/secp256k1-zkp/blob/8fd97d8/include/secp256k1_musig.h#L326
  // TODO: Should we do more to prevent nonce reuse?
  function nonceGen({
    sessionId,
    secretKey,
    message,
    aggregatePublicKey,
    extraInput,
  }: {
    sessionId: Uint8Array;
    secretKey?: Uint8Array;
    message?: Uint8Array;
    aggregatePublicKey?: Uint8Array;
    extraInput?: Uint8Array;
  }): { secretNonce: Uint8Array; publicNonce: Uint8Array } {
    const messages: Uint8Array[] = [];
    messages.push(sessionId);
    messages.push(...normalizeNonceArg(secretKey));
    messages.push(...normalizeNonceArg(message));
    messages.push(...normalizeNonceArg(aggregatePublicKey));
    messages.push(...normalizeNonceArg(extraInput));
    const seed = ecc.taggedHash(TAGS.musig_nonce, ...messages);
    const secretNonce = new Uint8Array(64);
    const publicNonce = new Uint8Array(66);
    for (let i = 0; i < 2; i++) {
      const k = ecc.sha256(seed, Uint8Array.of(i));
      secretNonce.set(k, i * 32);
      publicNonce.set(ecc.getPublicKey(k), i * 33);
    }
    return { secretNonce, publicNonce };
  }

  function nonceAgg(nonces: Uint8Array[]): Uint8Array {
    const noncePoints = nonces.map((nonce) => [nonce.subarray(0, 33), nonce.subarray(33)]);
    const aggNonces = noncePoints.reduce((prev, cur) => [
      ecc.pointAdd(prev[0], cur[0], false),
      ecc.pointAdd(prev[1], cur[1], false),
    ]);
    return Buffer.concat(aggNonces.map((nonce) => ecc.pointCompress(nonce, true)));
  }

  function nonceProcess(
    aggNonce: Uint8Array,
    message: Uint8Array,
    cache: KeyAggCache
  ): ProcessedNonce {
    const pubKeyX = pointX(cache.publicKey);

    const coefficient = ecc.taggedHash(TAGS.musig_noncecoef, aggNonce, pubKeyX, message);

    const aggNonces = [aggNonce.subarray(0, 33), aggNonce.subarray(33)];
    const finalNonce = ecc.pointAdd(
      aggNonces[0],
      ecc.pointMultiply(aggNonces[1], coefficient, false),
      false
    );
    if (!finalNonce) throw new Error('Unexpected final nonce at infinity');

    const finalNonceX = pointX(finalNonce);
    const challenge = ecc.secretMod(ecc.taggedHash(TAGS.challenge, finalNonceX, pubKeyX, message));

    let sPart: Uint8Array = U8A0;
    if (compare32b(cache.tweak, U8A0) !== 0) {
      sPart = ecc.secretMultiply(challenge, cache.tweak);
      if (!hasEvenY(cache.publicKey)) {
        sPart = ecc.secretNegate(sPart);
      }
    }

    return new ProcessedNonce(!hasEvenY(finalNonce), finalNonceX, coefficient, challenge, sPart);
  }

  function partialVerifyInner({
    sig,
    publicKey,
    publicNonce,
    cache,
    processedNonce,
  }: {
    sig: Uint8Array;
    publicKey: Uint8Array;
    publicNonce: Uint8Array | [Uint8Array, Uint8Array];
    cache: KeyAggCache;
    processedNonce: ProcessedNonce;
  }): boolean {
    const publicNonces = Array.isArray(publicNonce)
      ? publicNonce
      : [publicNonce.subarray(0, 33), publicNonce.subarray(33)];

    let rj = ecc.pointAdd(
      publicNonces[0],
      ecc.pointMultiply(publicNonces[1], processedNonce.coefficient, false),
      false
    );
    if (!rj) throw new Error('Unexpected public nonce at infinity');
    if (processedNonce.finalNonceHasOddY) {
      rj = ecc.pointNegate(rj);
    }

    // negative of the implementation in libsecp256k1-zkp due to a different but
    // algebraically identical verification equation used for convenience
    if (hasEvenY(cache.publicKey) === cache.parity) {
      publicKey = ecc.pointNegate(publicKey);
    }

    const a = cache.coefficient(publicKey);
    const ea = ecc.secretMultiply(processedNonce.challenge, a);

    const ver = ecc.pointAdd(rj, ecc.pointMultiply(publicKey, ea, false), true);
    if (!ver) return false;
    const sG = ecc.getPublicKey(sig, true);
    return ver[0] === sG[0] && compare32b(ver.slice(1), sG.slice(1)) === 0;
  }

  function partialSign({
    message,
    secretKey,
    nonce,
    aggNonce,
    session,
  }: {
    message: Uint8Array;
    secretKey: Uint8Array;
    nonce: Nonce;
    aggNonce: Uint8Array;
    session: KeyAggSession;
  }): { sig: Uint8Array; session: Uint8Array } {
    const cache = KeyAggCache.load(session);
    const processedNonce = nonceProcess(aggNonce, message, cache);
    const secretNonces = [nonce.secretNonce.slice(0, 32), nonce.secretNonce.slice(32)];
    // Do this before we (potentially) modify the private nonces.
    const publicNonce: Uint8Array | [Uint8Array, Uint8Array] = nonce.publicNonce || [
      ecc.getPublicKey(secretNonces[0], false),
      ecc.getPublicKey(secretNonces[1], false),
    ];

    if (processedNonce.finalNonceHasOddY) {
      for (let i = 0; i < secretNonces.length; i++) {
        secretNonces[i] = ecc.secretNegate(secretNonces[i]);
      }
    }

    const publicKey = ecc.getPublicKey(secretKey, false);
    const a = cache.coefficient(pointX(publicKey));

    // double-negative of the implementation in libsecp256k1-zkp
    if ((hasEvenY(publicKey) !== cache.parity) !== hasEvenY(cache.publicKey)) {
      secretKey = ecc.secretNegate(secretKey);
    }
    const ad = ecc.secretMultiply(a, secretKey);
    const ead = ecc.secretMultiply(processedNonce.challenge, ad);
    const bk2 = ecc.secretMultiply(processedNonce.coefficient, secretNonces[1]);
    const sig = ecc.secretAdd(ead, ecc.secretAdd(secretNonces[0], bk2));

    const verificationKey = pointX(publicKey);
    const valid = partialVerifyInner({
      sig,
      publicKey: verificationKey,
      publicNonce,
      cache,
      processedNonce,
    });
    if (!valid) throw new Error('Partial signature failed verification');

    return { sig, session: processedNonce.dump() };
  }

  function partialVerify({
    sig,
    message,
    publicKey,
    publicNonce,
    aggNonce,
    keyAggSession,
    session,
  }: {
    sig: Uint8Array;
    message: Uint8Array;
    publicKey: Uint8Array;
    publicNonce: Uint8Array;
    aggNonce: Uint8Array;
    keyAggSession: KeyAggSession;
    session?: Uint8Array;
  }): false | { session: Uint8Array } {
    const cache = KeyAggCache.load(keyAggSession);
    const processedNonce = session
      ? ProcessedNonce.load(session)
      : nonceProcess(aggNonce, message, cache);

    const valid = partialVerifyInner({
      sig,
      publicKey: pointX(publicKey),
      publicNonce,
      cache,
      processedNonce,
    });
    return valid && { session: processedNonce.dump() };
  }

  // X-only keys in
  function keyAgg(
    publicKeys: Uint8Array[],
    opts: {
      tweaks?: Uint8Array[];
      tweaksXOnly?: boolean[];
      sort?: boolean;
    } = {}
  ): AggregatePublicKey {
    let cache = KeyAggCache.fromPublicKeys(publicKeys, opts.sort);
    if (opts.tweaks !== undefined) cache = cache.addTweaks(opts.tweaks, opts.tweaksXOnly);
    return cache.toAggregatePublicKey();
  }

  function addTweaks(
    keyAggSession: KeyAggSession,
    tweaks: Uint8Array[],
    tweaksXOnly?: boolean[]
  ): AggregatePublicKey {
    let cache = KeyAggCache.load(keyAggSession);
    cache = cache.addTweaks(tweaks, tweaksXOnly);
    return cache.toAggregatePublicKey();
  }

  function signAgg(sigs: Uint8Array[], session: Uint8Array): Uint8Array {
    const processedNonce = ProcessedNonce.load(session);
    return NBuffer.concat([
      processedNonce.finalNonceX,
      sigs.reduce((prev, cur) => ecc.secretAdd(prev, cur), processedNonce.sPart),
    ]);
  }

  return {
    keyAgg,
    addTweaks,
    nonceGen,
    nonceAgg,
    partialSign,
    partialVerify,
    signAgg,
  };
}
