/*! musig-js - MIT License (c) 2022 Brandon Black */
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki

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
    opts?: {
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
    msg,
    aggregatePublicKey,
    extraInput,
  }: {
    sessionId: Uint8Array;
    secretKey?: Uint8Array;
    msg?: Uint8Array;
    aggregatePublicKey?: Uint8Array;
    extraInput?: Uint8Array;
  }): { secretNonce: Uint8Array; publicNonce: Uint8Array };

  nonceAgg(nonces: Uint8Array[]): Uint8Array;

  partialSign({
    msg,
    secretKey,
    nonce,
    aggNonce,
    keyAggSession,
  }: {
    msg: Uint8Array;
    secretKey: Uint8Array;
    nonce: Nonce;
    aggNonce: Uint8Array;
    keyAggSession: KeyAggSession;
  }): MuSigPartialSig;

  partialVerify({
    sig,
    msg,
    publicKey,
    publicNonce,
    aggNonce,
    keyAggSession,
    signingSession,
  }: {
    sig: Uint8Array;
    msg: Uint8Array;
    publicKey: Uint8Array;
    publicNonce: Uint8Array;
    aggNonce: Uint8Array;
    keyAggSession: KeyAggSession;
    signingSession?: Uint8Array;
  }): false | MuSigPartialSig;

  signAgg(sigs: Uint8Array[], signingSession: Uint8Array): Uint8Array;
}

export interface Crypto {
  /**
   * Adds a tweak to a point.
   *
   * @param p A point, compressed or uncompressed
   * @param t A tweak, 0 < t < n
   * @param compressed Whether the resulting point should be compressed.
   * @returns The tweaked point, compressed or uncompressed, null if the result
   * is the point at infinity.
   */
  pointAddTweak(p: Uint8Array, t: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Adds two points.
   *
   * @param a An addend point, compressed or uncompressed
   * @param b An addend point, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The sum point, compressed or uncompressed, null if the result is
   * the point at infinity.
   */
  pointAdd(a: Uint8Array, b: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Multiplies a point by a scalar.
   *
   * @param p A point multiplicand, compressed or uncompressed
   * @param a The multiplier, 0 < a < n
   * @param compressed Whether the resulting point should be compressed.
   * @returns The product point, compressed or uncompressed, null if the result
   * is the point at infinity.
   */
  pointMultiply(p: Uint8Array, a: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Negates a point, ie. returns the point with the opposite parity.
   *
   * @param p A point to negate, compressed or uncompressed
   * @returns The negated point, with same compression as input.
   */
  pointNegate(p: Uint8Array): Uint8Array;

  /**
   * Negates a point, ie. returns the point with the opposite parity.
   *
   * @param p A point format, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The point, compressed or uncompressed.
   */
  pointCompress(p: Uint8Array, compressed: boolean): Uint8Array;

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
   * @param p x-only, compressed or uncompressed
   * @returns the x coordinate of p
   */
  pointX(p: Uint8Array): Uint8Array;

  /**
   * @param p a point, compressed or uncompressed
   * @returns true if p has an even y coordinate, false otherwise
   */
  hasEvenY(p: Uint8Array): boolean;

  /**
   * Gets a public key for secret key.
   *
   * @param s Secret key
   * @param compressed Whether the resulting point should be compressed.
   * @returns The public key, compressed or uncompressed
   */
  getPublicKey(s: Uint8Array, compressed: boolean): Uint8Array | null;

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

const U8A0 = new Uint8Array(32);

/**
 * Compares two Uint8Arrays in byte order.
 * @returns < 0, 0, > 0 if a is < b, === b or > b respectively
 */
function compare32b(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== 32 || b.length !== 32) throw new Error('Can only compare 32 byte arrays');
  const aD = new DataView(a.buffer, a.byteOffset, a.length);
  const bD = new DataView(b.buffer, b.byteOffset, b.length);
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
  keyAggSession: KeyAggSession;
}

export interface MuSigPartialSig {
  sig: Uint8Array;
  signingSession: Uint8Array;
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
        if (coef === undefined) return evenPublicKeys[i];
        const spk = ecc.pointMultiply(evenPublicKeys[i], coef, false);
        if (!spk) throw new Error('Point at infinity during aggregation');
        return spk;
      });

      let publicKey: Uint8Array | null = shiftedPublicKeys[0];
      for (let i = 1; i < shiftedPublicKeys.length; i++) {
        publicKey = ecc.pointAdd(publicKey, shiftedPublicKeys[i], false);
        if (!publicKey) throw new Error('Point at infinty during aggregation');
      }
      return cache.copyWith(publicKey);
    }

    assertValidity(): void {
      if (
        this.publicKey.length !== 65 ||
        !ecc.isPoint(this.publicKey) ||
        this.publicKeyHash.length !== 32 ||
        (compare32b(this.secondPublicKeyX, U8A0) !== 0 &&
          !ecc.isXOnlyPoint(this.secondPublicKeyX)) ||
        (compare32b(this.tweak, U8A0) !== 0 && !ecc.isSecret(this.tweak))
      )
        throw new Error('Invalid KeyAggCache');
    }

    coefficient(publicKey: Uint8Array): Uint8Array | undefined {
      if (compare32b(publicKey, this.secondPublicKeyX) === 0) return undefined;
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
      let publicKey: Uint8Array | null = this.publicKey;
      let parity = this.parity;
      let tweak = this.tweak;

      for (let i = 0; i < tweaks.length; i++) {
        if (!ecc.hasEvenY(publicKey) && tweaksXOnly[i]) {
          parity = !parity;
          tweak = ecc.secretNegate(tweak);
          publicKey = ecc.pointNegate(publicKey); // -1 * Q[v-1]
        }
        publicKey = ecc.pointAddTweak(publicKey, tweaks[i], false); // +/-Q + tG
        if (!publicKey) throw new Error('Tweak failed');
        tweak = ecc.secretAdd(tweak, tweaks[i]);
      }

      return this.copyWith(publicKey, parity, tweak);
    }

    dump(): KeyAggSession {
      const rest = new Uint8Array(130);
      rest.set(this.publicKey, 0);
      rest.set(this.secondPublicKeyX, 65);
      rest[97] = this.parity ? 1 : 0;
      rest.set(this.tweak, 98);
      return { base: this.publicKeyHash, rest };
    }
    static load(session: KeyAggSession): KeyAggCache {
      // 32, and 65+32+1+32
      if (session.base.length !== 32 || session.rest.length !== 130)
        throw new TypeError(
          `expected 32 + 130 bytes, not ${session.base.length} + ${session.rest.length}`
        );
      const cache = new KeyAggCache(
        session.base,
        session.rest.subarray(65, 97),
        session.rest.subarray(0, 65),
        session.rest[97] === 0x01,
        session.rest.subarray(98, 130),
        _coefCache.get(session.base)
      );
      cache.assertValidity();
      return cache;
    }
    toAggregatePublicKey(): AggregatePublicKey {
      return {
        parity: ecc.hasEvenY(this.publicKey) ? 0 : 1,
        publicKey: ecc.pointX(this.publicKey),
        keyAggSession: this.dump(),
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
        session.subarray(1, 33),
        session.subarray(33, 65),
        session.subarray(65, 97),
        session.subarray(97)
      );
    }
    assertValidity(): void {
      if (
        !ecc.isXOnlyPoint(this.finalNonceX) ||
        !ecc.isSecret(this.coefficient) ||
        !ecc.isSecret(this.challenge) ||
        (compare32b(this.sPart, U8A0) !== 0 && !ecc.isSecret(this.sPart))
      )
        throw new Error('Invalid ProcessedNonce');
    }
    dump(): Uint8Array {
      const session = new Uint8Array(129);
      session[0] = this.finalNonceHasOddY ? 1 : 0;
      session.set(this.finalNonceX, 1);
      session.set(this.coefficient, 33);
      session.set(this.challenge, 65);
      session.set(this.sPart, 97);
      return session;
    }
  }

  function normalizeNonceArg(p?: Uint8Array): [Uint8Array] | [Uint8Array, Uint8Array] {
    if (!p) return [Uint8Array.of(0)];
    if (p.length !== 32) throw new Error('Expected 32 bytes');
    return [Uint8Array.of(32), p];
  }

  function nonceProcess(aggNonce: Uint8Array, msg: Uint8Array, cache: KeyAggCache): ProcessedNonce {
    const pubKeyX = ecc.pointX(cache.publicKey);

    const coefficient = ecc.taggedHash(TAGS.musig_noncecoef, aggNonce, pubKeyX, msg);

    const aggNonces = [aggNonce.subarray(0, 33), aggNonce.subarray(33)];
    const bK2 = ecc.pointMultiply(aggNonces[1], coefficient, false);
    if (!bK2) throw new Error('Nonce part at infinity');
    const finalNonce = ecc.pointAdd(aggNonces[0], bK2, false);
    if (!finalNonce) throw new Error('Unexpected final nonce at infinity');

    const finalNonceX = ecc.pointX(finalNonce);
    const challenge = ecc.secretMod(ecc.taggedHash(TAGS.challenge, finalNonceX, pubKeyX, msg));

    let sPart: Uint8Array = U8A0;
    if (compare32b(cache.tweak, U8A0) !== 0) {
      sPart = ecc.secretMultiply(challenge, cache.tweak);
      if (!ecc.hasEvenY(cache.publicKey)) {
        sPart = ecc.secretNegate(sPart);
      }
    }

    return new ProcessedNonce(
      !ecc.hasEvenY(finalNonce),
      finalNonceX,
      coefficient,
      challenge,
      sPart
    );
  }

  function partialVerifyInner({
    sig,
    publicKeyX,
    publicNonces,
    cache,
    processedNonce,
  }: {
    sig: Uint8Array;
    publicKeyX: Uint8Array;
    publicNonces: [Uint8Array, Uint8Array];
    cache: KeyAggCache;
    processedNonce: ProcessedNonce;
  }): boolean {
    const bK2 = ecc.pointMultiply(publicNonces[1], processedNonce.coefficient, false);
    if (!bK2) throw new Error('Nonce part at infinity');
    let rj = ecc.pointAdd(publicNonces[0], bK2, false);
    if (!rj) throw new Error('Unexpected public nonce at infinity');
    if (processedNonce.finalNonceHasOddY) rj = ecc.pointNegate(rj);

    let publicKey = ecc.liftX(publicKeyX);
    if (!publicKey) throw new Error('Invalid verification key');
    // negative of the implementation in libsecp256k1-zkp due to a different but
    // algebraically identical verification equation used for convenience
    if (ecc.hasEvenY(cache.publicKey) === cache.parity) {
      publicKey = ecc.pointNegate(publicKey);
    }

    const a = cache.coefficient(ecc.pointX(publicKey));
    const ea =
      a === undefined ? processedNonce.challenge : ecc.secretMultiply(processedNonce.challenge, a);

    const eaP = ecc.pointMultiply(publicKey, ea, false);
    if (!eaP) return false;
    const ver = ecc.pointAdd(rj, eaP, true);
    if (!ver) return false;
    const sG = ecc.getPublicKey(sig, true);
    if (!sG) return false;
    return ver[0] === sG[0] && compare32b(ver.subarray(1), sG.subarray(1)) === 0;
  }

  function partialSignInner({
    msg,
    secretKey,
    publicKey,
    secretNonces,
    cache,
    processedNonce,
  }: {
    msg: Uint8Array;
    secretKey: Uint8Array;
    publicKey: Uint8Array;
    secretNonces: [Uint8Array, Uint8Array];
    cache: KeyAggCache;
    processedNonce: ProcessedNonce;
  }): Uint8Array {
    const bk2 = ecc.secretMultiply(processedNonce.coefficient, secretNonces[1]);
    let k1bk2 = ecc.secretAdd(secretNonces[0], bk2);
    if (processedNonce.finalNonceHasOddY) k1bk2 = ecc.secretNegate(k1bk2);

    // double-negative of the implementation in libsecp256k1-zkp
    if ((ecc.hasEvenY(publicKey) !== cache.parity) !== ecc.hasEvenY(cache.publicKey)) {
      secretKey = ecc.secretNegate(secretKey);
    }

    const a = cache.coefficient(ecc.pointX(publicKey));
    const ea =
      a === undefined ? processedNonce.challenge : ecc.secretMultiply(processedNonce.challenge, a);

    const ead = ecc.secretMultiply(ea, secretKey);
    const sig = ecc.secretAdd(ead, k1bk2);

    return sig;
  }

  return {
    keyAgg: (
      publicKeys: Uint8Array[],
      opts: {
        tweaks?: Uint8Array[];
        tweaksXOnly?: boolean[];
        sort?: boolean;
      } = {}
    ): AggregatePublicKey => {
      let cache = KeyAggCache.fromPublicKeys(publicKeys, opts.sort);
      if (opts.tweaks !== undefined) cache = cache.addTweaks(opts.tweaks, opts.tweaksXOnly);
      return cache.toAggregatePublicKey();
    },

    addTweaks: (
      keyAggSession: KeyAggSession,
      tweaks: Uint8Array[],
      tweaksXOnly?: boolean[]
    ): AggregatePublicKey => {
      let cache = KeyAggCache.load(keyAggSession);
      cache = cache.addTweaks(tweaks, tweaksXOnly);
      return cache.toAggregatePublicKey();
    },

    // See https://github.com/ElementsProject/secp256k1-zkp/blob/8fd97d8/include/secp256k1_musig.h#L326
    // TODO: Should we do more to prevent nonce reuse?
    nonceGen: ({
      sessionId,
      secretKey,
      msg,
      aggregatePublicKey,
      extraInput,
    }: {
      sessionId: Uint8Array;
      secretKey?: Uint8Array;
      msg?: Uint8Array;
      aggregatePublicKey?: Uint8Array;
      extraInput?: Uint8Array;
    }): { secretNonce: Uint8Array; publicNonce: Uint8Array } => {
      const seed = ecc.taggedHash(
        TAGS.musig_nonce,
        ...[
          sessionId,
          ...normalizeNonceArg(secretKey),
          ...normalizeNonceArg(msg),
          ...normalizeNonceArg(aggregatePublicKey),
          ...normalizeNonceArg(extraInput),
        ]
      );
      const secretNonce = new Uint8Array(64);
      const publicNonce = new Uint8Array(66);
      for (let i = 0; i < 2; i++) {
        const kH = ecc.sha256(seed, Uint8Array.of(i));
        const k = ecc.secretMod(kH);
        secretNonce.set(k, i * 32);
        const pub = ecc.getPublicKey(k, true);
        if (!pub) throw new Error('Secret nonce has no corresponding public nonce');
        publicNonce.set(pub, i * 33);
      }
      return { secretNonce, publicNonce };
    },

    nonceAgg: (nonces: Uint8Array[]): Uint8Array => {
      let aggNonces = [nonces[0].subarray(0, 33), nonces[0].subarray(33)];
      for (let i = 1; i < nonces.length; i++) {
        const K1 = ecc.pointAdd(aggNonces[0], nonces[i].subarray(0, 33), false);
        if (!K1) throw new Error('Agg nonce part at infinity');
        const K2 = ecc.pointAdd(aggNonces[1], nonces[i].subarray(33), false);
        if (!K2) throw new Error('Agg nonce part at infinity');
        aggNonces = [K1, K2];
      }
      const aggNonce = new Uint8Array(66);
      aggNonce.set(ecc.pointCompress(aggNonces[0], true), 0);
      aggNonce.set(ecc.pointCompress(aggNonces[1], true), 33);
      return aggNonce;
    },

    partialSign: ({
      msg,
      secretKey,
      nonce,
      aggNonce,
      keyAggSession,
    }: {
      msg: Uint8Array;
      secretKey: Uint8Array;
      nonce: Nonce;
      aggNonce: Uint8Array;
      keyAggSession: KeyAggSession;
    }): MuSigPartialSig => {
      const publicKey = ecc.getPublicKey(secretKey, false);
      if (!publicKey) throw new Error('Invalid secret key, no corresponding public key');
      const secretNonces: [Uint8Array, Uint8Array] = [
        nonce.secretNonce.subarray(0, 32),
        nonce.secretNonce.subarray(32),
      ];
      const cache = KeyAggCache.load(keyAggSession);
      const processedNonce = nonceProcess(aggNonce, msg, cache);
      const sig = partialSignInner({
        msg,
        secretKey,
        publicKey,
        secretNonces,
        cache,
        processedNonce,
      });

      let publicNonces: [Uint8Array, Uint8Array];
      if (nonce.publicNonce) {
        publicNonces = [nonce.publicNonce.subarray(0, 33), nonce.publicNonce.subarray(33)];
      } else {
        const pn1 = ecc.getPublicKey(secretNonces[0], false);
        const pn2 = ecc.getPublicKey(secretNonces[1], false);
        if (!pn1 || !pn2) throw new Error('Invalid secret nonce, no corresponding public nonce');
        publicNonces = [pn1, pn2];
      }
      const valid = partialVerifyInner({
        sig,
        publicKeyX: ecc.pointX(publicKey),
        publicNonces,
        cache,
        processedNonce,
      });
      if (!valid) throw new Error('Partial signature failed verification');
      return { sig, signingSession: processedNonce.dump() };
    },

    partialVerify: ({
      sig,
      msg,
      publicKey,
      publicNonce,
      aggNonce,
      keyAggSession,
      signingSession,
    }: {
      sig: Uint8Array;
      msg: Uint8Array;
      publicKey: Uint8Array;
      publicNonce: Uint8Array;
      aggNonce: Uint8Array;
      keyAggSession: KeyAggSession;
      signingSession?: Uint8Array;
    }): false | MuSigPartialSig => {
      const publicNonces: [Uint8Array, Uint8Array] = [
        publicNonce.subarray(0, 33),
        publicNonce.subarray(33),
      ];

      const cache = KeyAggCache.load(keyAggSession);
      const processedNonce = signingSession
        ? ProcessedNonce.load(signingSession)
        : nonceProcess(aggNonce, msg, cache);

      const valid = partialVerifyInner({
        sig,
        publicKeyX: publicKey,
        publicNonces,
        cache,
        processedNonce,
      });
      return valid && { sig, signingSession: processedNonce.dump() };
    },

    signAgg: (sigs: Uint8Array[], signingSession: Uint8Array): Uint8Array => {
      const processedNonce = ProcessedNonce.load(signingSession);
      const sig = new Uint8Array(64);
      sig.set(processedNonce.finalNonceX, 0);
      sig.set(
        sigs.reduce((prev, cur) => ecc.secretAdd(prev, cur), processedNonce.sPart),
        32
      );
      return sig;
    },
  };
}
