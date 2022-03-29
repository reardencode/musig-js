/*! musig-js - MIT License (c) 2022 Brandon Black */
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki
// Roughly based on the secp256k1-zkp implementation

export interface MuSig {
  /**
   * Performs MuSig key aggregation on 1+ x-only public keys.
   *
   * @param publicKeys array of x-only public keys to aggregate
   * @param opts.tweaks array of tweaks (0 < tweak < n) to apply to the aggregate key
   * @param opts.tweaksXOnly whether to perform x-only or ordinary tweaking per tweak
   * @param opts.sort if false, public keys are not sorted before aggregation
   * @returns An aggregate public key, its parity, and an opaque cache for use
   * in subsequent operations.
   */
  keyAgg(
    publicKeys: Uint8Array[],
    opts?: {
      tweaks?: Uint8Array[];
      tweaksXOnly?: boolean[];
      sort?: boolean;
    }
  ): AggregatePublicKey;

  /**
   * Apply a sequence of x-only or ordinary tweaks to an aggregate public key.
   *
   * @param keyAggSession the key aggregation session, as returned from `keyAgg`.
   * @param tweaks array of tweaks (0 < tweak < n) to apply to the aggregate key
   * @param tweaksXOnly whether to perform x-only or ordinary tweaking per tweak
   * @returns An aggregate public key, its parity, and an opaque cache for use
   * in subsequent operations.
   */
  addTweaks(
    keyAggSession: KeyAggSession,
    tweaks: Uint8Array[],
    tweaksXOnly?: boolean[]
  ): AggregatePublicKey;

  /**
   * Generate a MuSig nonce pair based on the provided values.
   *
   * @param sessionId if no secret key is provided, uniformly 32-bytes of
   * random data, otherwise a value guaranteed not to repeat for the secret key
   * @param secretKey the secret key which will eventually sign with this nonce
   * @param msg the messaeg which will eventually be signed with this nonce
   * @param aggregatePublicKey the x-coordinate of the aggregate public key
   * that this nonce will be signing a part of
   * @param extraInput 32-bytes of additional input which will contribute to
   * the generated nonce
   * @return the generated secret nonce (64 bytes), and its corresponding
   * public nonce (66 bytes)
   */
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

  /**
   * Combine public nonces from all signers into a single aggregate public nonce.
   *
   * Per the spec, this function prefers to succeed with an invalid nonce at
   * infinity than to fail, to enable a dishonest signer to be detected later.
   *
   * @param nonces n-signers public nonces (66-bytes each)
   * @return the aggregate public nonce (66-bytes)
   */
  nonceAgg(nonces: Uint8Array[]): Uint8Array;

  /**
   * Creates an opaque cached signing session for used in partial signing,
   * partial verification, or signature aggregation.
   *
   * @param aggNonce this signing session's aggregate nonce
   * @param msg the 32-byte message to sign for, most commonly a transaction hash.
   * @param keyAggSession information about the aggregate key being signed for
   * @return opaque signing session
   */
  createSigningSession(
    aggNonce: Uint8Array,
    msg: Uint8Array,
    keyAggSession: KeyAggSession
  ): Uint8Array;

  /**
   * Creates a MuSig partial signature for the given values.
   *
   * Verifies the resulting partial signature by default, as recommended in the
   * specification.
   *
   * Note: Calling `partialSign` with the same `secretNonce` more than once
   * when any other input changes will leak the signer's secret key.
   *
   * @param msg the 32-byte message to sign for, most commonly a transaction hash.
   * @param secretKey signer's secret key
   * @param nonce signer's secret (and optionally public) nonce
   * @param aggNonce this signing session's aggregate nonce
   * @param keyAggSession information about the aggregate key being signed for
   * @param signingSession opaque cached signing session
   * @param verify if false, don't verify partial signature
   * @return resulting signature, and opaque signing session
   */
  partialSign({
    msg,
    secretKey,
    nonce,
    aggNonce,
    keyAggSession,
    signingSession,
    verify,
  }: {
    msg: Uint8Array;
    secretKey: Uint8Array;
    nonce: Nonce;
    aggNonce: Uint8Array;
    keyAggSession: KeyAggSession;
    signingSession?: Uint8Array;
    verify?: boolean;
  }): MuSigPartialSig;

  /**
   * Verifies a MuSig partial signature for the given values.
   *
   * @param sig the 32-byte MuSig partial signature to verify
   * @param msg the 32-byte message to sign for, most commonly a transaction hash
   * @param publicKey signer's public key
   * @param publicNonce signer's public nonce
   * @param aggNonce this signing session's aggregate nonce
   * @param keyAggSession information about the aggregate key being signed for
   * @param signingSession opaque cached signing session
   * @return false if the verification fails, or opaque signing session
   * (truthy) if verification succeeds.
   */
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

  /**
   * Aggregates MuSig partial signatures.
   *
   * @param sigs array of 32-bytes MuSig partial signatures.
   * @param signingSession opaque cached signing session
   * @return the resulting aggregate signature.
   */
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
   * This function may use non-constant time operations, as no secret
   * information is processed.
   *
   * @param p A point multiplicand, compressed or uncompressed
   * @param a The multiplier, 0 < a < n
   * @param compressed Whether the resulting point should be compressed.
   * @returns The product point, compressed or uncompressed, null if the result
   * is the point at infinity.
   */
  pointMultiplyUnsafe(p: Uint8Array, a: Uint8Array, compressed: boolean): Uint8Array | null;

  /**
   * Multiplies point 1 by a scalar and adds it to point 2.
   * This function may use non-constant time operations, as no secret
   * information is processed.
   *
   * @param p1 point multiplicand, compressed or uncompressed
   * @param a The multiplier, 0 < a < n
   * @param p2 point addend, compressed or uncompressed
   * @param compressed Whether the resulting point should be compressed.
   * @returns The product/sum point, compressed or uncompressed, null if the
   * result is the point at infinity.
   */
  pointMultiplyAndAddUnsafe(
    p1: Uint8Array,
    a: Uint8Array,
    p2: Uint8Array,
    compressed: boolean
  ): Uint8Array | null;

  /**
   * Negates a point, ie. returns the point with the opposite parity.
   *
   * @param p A point to negate, compressed or uncompressed
   * @returns The negated point, with same compression as input.
   */
  pointNegate(p: Uint8Array): Uint8Array;

  /**
   * Compresses a point.
   *
   * @param p A point, compressed or uncompressed
   * @returns The point, compressed.
   */
  pointCompress(p: Uint8Array): Uint8Array;

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

export interface Nonce {
  secretNonce: Uint8Array; // 64 bytes
  publicNonce?: Uint8Array; // 66 bytes
}

export interface KeyAggSession {
  base: Uint8Array; // 32 bytes
  rest: Uint8Array; // 130 bytes
}

export interface AggregatePublicKey {
  parity: 0 | 1;
  publicKey: Uint8Array; // 32 bytes
  keyAggSession: KeyAggSession;
}

export interface MuSigPartialSig {
  sig: Uint8Array;
  signingSession: Uint8Array; // 161 bytes
}

const TAGS = {
  challenge: 'BIP0340/challenge',
  keyagg_list: 'KeyAgg list',
  keyagg_coef: 'KeyAgg coefficient',
  musig_nonce: 'MuSig/nonce',
  musig_noncecoef: 'MuSig/noncecoef',
} as const;

const U8A0 = new Uint8Array(32);
const U8A1 = new Uint8Array(32);
U8A1[31] = 1;

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

function noneNull(keys: Array<Uint8Array | null>): keys is Uint8Array[] {
  return keys.every((pk) => pk !== null);
}

// Caches coefficients associated with a specific publicKeyHash
const _coefCache = new WeakMap<Uint8Array, Map<string, Uint8Array>>();

export function MuSigFactory(ecc: Crypto): MuSig {
  function coefficient(
    publicKeyHash: Uint8Array,
    publicKey: Uint8Array,
    secondPublicKey?: Uint8Array
  ): Uint8Array {
    let coefCache = _coefCache.get(publicKeyHash);
    if (coefCache === undefined) {
      coefCache = new Map<string, Uint8Array>();
      _coefCache.set(publicKeyHash, coefCache);
    }
    const key = Buffer.from(publicKey).toString('hex');
    let coef = coefCache.get(key);
    if (coef === undefined) {
      coef = U8A1;
      if (!secondPublicKey || compare32b(publicKey, secondPublicKey) !== 0)
        coef = ecc.taggedHash(TAGS.keyagg_coef, publicKeyHash, publicKey);
      coefCache.set(key, coef);
    }
    return coef;
  }

  // Information needed to partially sign for an aggregate public key
  class KeyAggCache {
    private constructor(
      readonly publicKeyHash: Uint8Array, // L, to determine key aggregation coefficients when signing
      readonly publicKey: Uint8Array, // Current xy aggregate public key
      // If > 1 unique X-values in the key, keys with Xs identical to 2nd unique X use coffecient = 1
      readonly secondPublicKey: Uint8Array | undefined,
      readonly parity: boolean = false,
      readonly tweak: Uint8Array = U8A0
    ) {
      if (
        publicKey.length !== 65 ||
        !ecc.isPoint(publicKey) ||
        publicKeyHash.length !== 32 ||
        (secondPublicKey !== undefined && !ecc.isXOnlyPoint(secondPublicKey)) ||
        (compare32b(tweak, U8A0) !== 0 && !ecc.isSecret(tweak))
      )
        throw new Error('Invalid KeyAggCache');
    }
    private copyWith(publicKey: Uint8Array, parity?: boolean, tweak?: Uint8Array): KeyAggCache {
      const cache = new KeyAggCache(
        this.publicKeyHash,
        publicKey,
        this.secondPublicKey,
        parity,
        tweak
      );
      return cache;
    }

    static fromPublicKeys(publicKeys: Uint8Array[], sort = true): KeyAggCache {
      if (publicKeys.length === 0) throw new Error('Cannot aggregate 0 public keys');
      if (sort) publicKeys.sort((a, b) => compare32b(a, b));
      const evenPublicKeys = publicKeys.map((pk) => ecc.liftX(pk));
      if (!noneNull(evenPublicKeys)) throw new Error('Invalid public key');

      // Index of the first occurrence of the second unique public key X.
      const pkIdx2 = publicKeys.findIndex((pk) => compare32b(pk, publicKeys[0]) !== 0);
      const secondPublicKey = publicKeys[pkIdx2]; // undefined if pkIdx2 === -1

      const publicKeyHash = ecc.taggedHash(TAGS.keyagg_list, ...publicKeys);

      // Use first occurrence of second unique key, or first key as initial value for aggregation.
      const initialIdx = pkIdx2 === -1 ? 0 : pkIdx2;
      let publicKey: Uint8Array | null = evenPublicKeys[initialIdx];
      if (initialIdx === 0) {
        // If no 2nd unique key, multiply initial key by its coefficient.
        const coef = coefficient(publicKeyHash, publicKeys[initialIdx], secondPublicKey);
        publicKey = ecc.pointMultiplyUnsafe(publicKey, coef, false);
        if (publicKey === null) throw new Error('Point at infinity during aggregation');
      }

      // We do ^ to do save 1 ECC multiplication, while working within
      // constraints of functions offered by the two ECC libraries we support.
      for (let i = 0; i < publicKeys.length; i++) {
        if (i === initialIdx) continue;
        const coef = coefficient(publicKeyHash, publicKeys[i], secondPublicKey);
        publicKey = ecc.pointMultiplyAndAddUnsafe(evenPublicKeys[i], coef, publicKey, false);
        if (publicKey === null) throw new Error('Point at infinity during aggregation');
      }

      return new KeyAggCache(publicKeyHash, publicKey, secondPublicKey);
    }

    coefficient(publicKey: Uint8Array): Uint8Array {
      return coefficient(this.publicKeyHash, publicKey, this.secondPublicKey);
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
      rest.set(this.secondPublicKey || U8A0, 65);
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
      const secondPublicKey = session.rest.subarray(65, 97);
      const cache = new KeyAggCache(
        session.base,
        session.rest.subarray(0, 65),
        compare32b(secondPublicKey, U8A0) === 0 ? undefined : secondPublicKey,
        session.rest[97] === 0x01,
        session.rest.subarray(98, 130)
      );
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

  // Information need to partially sign, partially verify, or aggregate partial signatures.
  class ProcessedNonce {
    private constructor(
      readonly finalNonce: Uint8Array,
      readonly coefficient: Uint8Array,
      readonly challenge: Uint8Array,
      readonly sPart: Uint8Array
    ) {
      if (
        !ecc.isPoint(finalNonce) ||
        !ecc.isSecret(coefficient) ||
        !ecc.isSecret(challenge) ||
        (compare32b(sPart, U8A0) !== 0 && !ecc.isSecret(sPart))
      )
        throw new Error('Invalid ProcessedNonce');
    }

    static process(aggNonce: Uint8Array, msg: Uint8Array, cache: KeyAggCache): ProcessedNonce {
      const pubKeyX = ecc.pointX(cache.publicKey);

      const coefficient = ecc.taggedHash(TAGS.musig_noncecoef, aggNonce, pubKeyX, msg);

      const aggNonces = [aggNonce.subarray(0, 33), aggNonce.subarray(33)];
      const r = ecc.pointMultiplyAndAddUnsafe(aggNonces[1], coefficient, aggNonces[0], false);
      if (!r) throw new Error('Unexpected final nonce at infinity');

      const challenge = ecc.secretMod(ecc.taggedHash(TAGS.challenge, ecc.pointX(r), pubKeyX, msg));

      let sPart: Uint8Array = ecc.secretMultiply(challenge, cache.tweak);
      if (!ecc.hasEvenY(cache.publicKey)) {
        sPart = ecc.secretNegate(sPart);
      }

      return new ProcessedNonce(r, coefficient, challenge, sPart);
    }

    static load(session: Uint8Array): ProcessedNonce {
      if (session.length !== 161) throw new TypeError(`expected 161 bytes, not ${session.length}`);
      return new ProcessedNonce(
        session.subarray(0, 65),
        session.subarray(65, 97),
        session.subarray(97, 129),
        session.subarray(129)
      );
    }

    dump(): Uint8Array {
      const session = new Uint8Array(161);
      session.set(this.finalNonce, 0);
      session.set(this.coefficient, 65);
      session.set(this.challenge, 97);
      session.set(this.sPart, 129);
      return session;
    }
  }

  function normalizeNonceArg(p?: Uint8Array): [Uint8Array] | [Uint8Array, Uint8Array] {
    if (!p) return [Uint8Array.of(0)];
    if (p.length !== 32) throw new Error('Expected 32 bytes');
    return [Uint8Array.of(32), p];
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
    const { challenge, coefficient, finalNonce } = processedNonce;
    let rj = ecc.pointMultiplyAndAddUnsafe(publicNonces[1], coefficient, publicNonces[0], false);
    if (!rj) throw new Error('Unexpected public nonce at infinity');
    if (!ecc.hasEvenY(finalNonce)) rj = ecc.pointNegate(rj);

    let publicKey = ecc.liftX(publicKeyX);
    if (!publicKey) throw new Error('Invalid verification key');
    // negative of the implementation in libsecp256k1-zkp due to a different but
    // algebraically identical verification equation used for convenience
    if (ecc.hasEvenY(cache.publicKey) === cache.parity) {
      publicKey = ecc.pointNegate(publicKey);
    }

    const ea = ecc.secretMultiply(challenge, cache.coefficient(ecc.pointX(publicKey)));

    const ver = ecc.pointMultiplyAndAddUnsafe(publicKey, ea, rj, true);
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
    const { challenge, coefficient, finalNonce } = processedNonce;
    const bk2 = ecc.secretMultiply(coefficient, secretNonces[1]);
    let k1bk2 = ecc.secretAdd(secretNonces[0], bk2);
    if (!ecc.hasEvenY(finalNonce)) k1bk2 = ecc.secretNegate(k1bk2);

    // double-negative of the implementation in libsecp256k1-zkp
    if ((ecc.hasEvenY(publicKey) !== cache.parity) !== ecc.hasEvenY(cache.publicKey)) {
      secretKey = ecc.secretNegate(secretKey);
    }

    const ea = ecc.secretMultiply(challenge, cache.coefficient(ecc.pointX(publicKey)));

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
        const K2 = ecc.pointAdd(aggNonces[1], nonces[i].subarray(33), false);
        if (!K1 || !K2) {
          const G = ecc.getPublicKey(U8A1, true);
          aggNonces = [G!, G!];
          break;
        }
        aggNonces = [K1, K2];
      }
      const aggNonce = new Uint8Array(66);
      aggNonce.set(ecc.pointCompress(aggNonces[0]), 0);
      aggNonce.set(ecc.pointCompress(aggNonces[1]), 33);
      return aggNonce;
    },

    createSigningSession: (
      aggNonce: Uint8Array,
      msg: Uint8Array,
      keyAggSession: KeyAggSession
    ): Uint8Array => ProcessedNonce.process(aggNonce, msg, KeyAggCache.load(keyAggSession)).dump(),

    partialSign: ({
      msg,
      secretKey,
      nonce,
      aggNonce,
      keyAggSession,
      signingSession,
      verify = true,
    }: {
      msg: Uint8Array;
      secretKey: Uint8Array;
      nonce: Nonce;
      aggNonce: Uint8Array;
      keyAggSession: KeyAggSession;
      signingSession?: Uint8Array;
      verify: boolean;
    }): MuSigPartialSig => {
      const publicKey = ecc.getPublicKey(secretKey, false);
      if (!publicKey) throw new Error('Invalid secret key, no corresponding public key');
      const secretNonces: [Uint8Array, Uint8Array] = [
        nonce.secretNonce.subarray(0, 32),
        nonce.secretNonce.subarray(32),
      ];
      const cache = KeyAggCache.load(keyAggSession);
      const processedNonce = signingSession
        ? ProcessedNonce.load(signingSession)
        : ProcessedNonce.process(aggNonce, msg, cache);
      const sig = partialSignInner({
        msg,
        secretKey,
        publicKey,
        secretNonces,
        cache,
        processedNonce,
      });

      if (verify) {
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
      }
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
        : ProcessedNonce.process(aggNonce, msg, cache);

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
      const { finalNonce, sPart } = ProcessedNonce.load(signingSession);
      const aggS = sigs.reduce((a, b) => ecc.secretAdd(a, b), sPart);
      const sig = new Uint8Array(64);
      sig.set(finalNonce.slice(1, 33), 0);
      sig.set(aggS, 32);
      return sig;
    },
  };
}
