/*! musig-js - MIT License (c) 2022 Brandon Black */
// https://github.com/ElementsProject/secp256k1-zkp/blob/master/doc/musig-spec.mediawiki
// Roughly based on the secp256k1-zkp implementation

export interface MuSig {
  /**
   * Gets the X-only public key associated with this context.
   *
   * @param ctx the key gen context or a signing session key
   * @returns the X-only public key associated with this context
   */
  getXOnlyPubkey(ctx: KeyGenContext | SessionKey): Uint8Array;

  /**
   * Gets the plain public key associated with this context.
   *
   * @param ctx the key gen context or a signing session key
   * @returns plain public key associated with this context in compressed DER format
   */
  getPlainPubkey(ctx: KeyGenContext | SessionKey): Uint8Array;

  /**
   * Sorts compressed DER format public keys lexicographically.
   *
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @returns sorted public keys (in a new array)
   */
  keySort(publicKeys: Uint8Array[]): Uint8Array[];

  /**
   * Performs MuSig key aggregation on 1+ x-only public keys.
   *
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 < tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @returns an opaque key gen context for use with other MuSig operations
   */
  keyAgg(publicKeys: Uint8Array[], ...tweaks: Tweak[]): KeyGenContext;

  /**
   * Apply one or more x-only or ordinary tweaks to an aggregate public key.
   *
   * @param ctx the key generation context, as returned from `keyAgg`.
   * @param tweaks tweaks (0 < tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @returns an opaque key gen context for use with other MuSig operations
   */
  addTweaks(ctx: KeyGenContext, ...tweaks: Tweak[]): KeyGenContext;

  /**
   * Generate a MuSig nonce pair based on the provided values.
   *
   * The caller must not use the same sessionId for multiple calls to nonceGen
   * with other parameters held constant.
   *
   * The secret nonce (97 bytes) is cached internally, and will be deleted
   * from the cache prior to use in a signature. The secret nonce will also be
   * deleted if the returned public nonce is deleted.
   *
   * @param sessionId if no secret key is provided, uniformly 32-bytes of
   * random data, otherwise a value guaranteed not to repeat for the secret
   * key. If no sessionId is provided a reasonably high quality random one will
   * be generated.
   * @param secretKey the secret key which will eventually sign with this nonce
   * @param publicKey the public key for which this nonce will be signed (required)
   * @param xOnlyPublicKey the x-coordinate of the aggregate public key that this
   * nonce will be signing a part of
   * @param msg the message which will eventually be signed with this nonce
   * (any possible Uint8Array length)
   * @param extraInput additional input which will contribute to the generated
   * nonce (0 <= extraInput.length <= 2^32-1)
   * @return the generated public nonce (66 bytes)
   */
  nonceGen(args: {
    sessionId?: Uint8Array;
    secretKey?: Uint8Array;
    publicKey: Uint8Array;
    xOnlyPublicKey?: Uint8Array;
    msg?: Uint8Array;
    extraInput?: Uint8Array;
  }): Uint8Array;

  /**
   * Add an externally generated nonce to the cache.
   *
   * NOT RECOMMENDED, but useful in testing at least.
   * @param publicNonce 66-byte public nonce (2 points in compressed DER)
   * @param secretNonce 97-byte secret nonce (2 32-byte scalars, and the public
   * key which will sign for this nonce in compressed DER)
   */
  addExternalNonce(publicNonce: Uint8Array, secretNonce: Uint8Array): void;

  /**
   * Combine public nonces from all signers into a single aggregate public nonce.
   *
   * Per the spec, this function prefers to succeed with an invalid nonce at
   * infinity than to fail, to enable a dishonest signer to be detected later.
   *
   * This can be run by an untrusted node without breaking the security of the
   * protocol. An untrusted aggregator can cause the protocol to fail, but not
   * forge a signature.
   *
   * @param nonces n-signers public nonces (66-bytes each)
   * @return the aggregate public nonce (66-bytes)
   */
  nonceAgg(nonces: Uint8Array[]): Uint8Array;

  /**
   * Creates an opaque signing session for used in partial signing, partial
   * verification, or signature aggregation. This may be saved by a
   * participant, but may not be provided by an untrusted party.
   *
   * @param aggNonce this signing session's aggregate nonce
   * @param msg the 32-byte message to sign for, most commonly a transaction hash.
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 < tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @return session key for `partialSign`, `partialVerify` and `signAgg`
   */
  startSigningSession(
    aggNonce: Uint8Array,
    msg: Uint8Array,
    publicKeys: Uint8Array[],
    ...tweaks: Tweak[]
  ): SessionKey;

  /**
   * Creates a MuSig partial signature for the given values.
   *
   * Verifies the resulting partial signature by default, as recommended in the
   * specification.
   *
   * Note: Calling `partialSign` with the same `publicNonce` more than once
   * will not work, as the corresponding secret nonce is deleted. Generate a
   * new public nonce and try again.
   *
   * @param secretKey signer's secret key
   * @param publicNonce signer's public nonce
   * @param sessionKey signing session key (from startSigningSession)
   * @param verify if false, don't verify partial signature
   * @return resulting signature
   */
  partialSign(args: {
    secretKey: Uint8Array;
    publicNonce: Uint8Array;
    sessionKey: SessionKey;
    verify?: boolean;
  }): Uint8Array;

  /**
   * Verifies a MuSig partial signature for the given values.
   *
   * @param sig the 32-byte MuSig partial signature to verify
   * @param msg the 32-byte message to sign for, most commonly a transaction hash
   * @param publicKey signer's public key
   * @param publicNonce signer's public nonce
   * @param aggNonce this signing session's aggregate nonce
   * @param sessionKey signing session key (from startSigningSession)
   * @return true if the partial signature is valid, otherwise false
   */
  partialVerify(args: {
    sig: Uint8Array;
    publicKey: Uint8Array;
    publicNonce: Uint8Array;
    sessionKey: SessionKey;
  }): boolean;

  /**
   * Aggregates MuSig partial signatures. May be run by an untrusted party.
   *
   * @param sigs array of 32-bytes MuSig partial signatures.
   * @param sessionKey signing session key (from startSigningSession)
   * @return the resulting aggregate signature.
   */
  signAgg(sigs: Uint8Array[], sessionKey: SessionKey): Uint8Array;

  /**
   * Deterministically generate nonces and partially sign for a MuSig key.
   * The security of this method depends on its being run after all other
   * parties have provided their nonces.
   *
   * @param secretKey signer's secret key
   * @param aggOtherNonce the result of calling `nonceAgg` on all other signing
   * parties' nonces
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 < tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @param msg the 32-byte message to sign for, most commonly a transaction hash.
   * @param rand optional additional randomness for nonce generation
   * @param verify if false, don't verify partial signature
   * @return resulting signature, session key (for signature aggregation), and
   * public nonce (for partial verification)
   */
  deterministicSign(args: {
    secretKey: Uint8Array;
    aggOtherNonce: Uint8Array;
    publicKeys: Uint8Array[];
    tweaks?: Tweak[];
    msg: Uint8Array;
    rand?: Uint8Array;
    verify?: boolean;
  }): {
    sig: Uint8Array;
    sessionKey: SessionKey;
    publicNonce: Uint8Array;
  };

  /**
   * Deterministically generate nonces. This is identical to deterministicSign,
   * except that it aborts after nonce generation and before signing, and
   * returns only the public nonce. This security of this method of nonce
   * generation depends on its being run after all other parties have provided
   * their nonces.
   *
   * A public nonce generated in this way cannot be directly used for signing
   * (no secret nonce is saved), but a matching partial signature can be
   * generated by subsequently calling deterministicSign with the same
   * arguments as the call to deterministicNonceGen.
   *
   * This can be useful in a case where a stateless signer only wants to
   * provide its partial signature after seeing valid partial signatures from
   * other parties.
   *
   * @param secretKey signer's secret key
   * @param aggOtherNonce the result of calling `nonceAgg` on all other signing
   * parties' nonces
   * @param publicKeys array of compressed DER encoded public keys to aggregate
   * @param tweaks tweaks (0 < tweak < n) to apply to the aggregate key,
   * and optionally booleans to indicate x-only tweaking
   * @param msg the 32-byte message to sign for, most commonly a transaction hash.
   * @param rand optional additional randomness for nonce generation
   * @param verify if false, don't verify partial signature
   * @return public nonce
   */
  deterministicNonceGen(args: {
    secretKey: Uint8Array;
    aggOtherNonce: Uint8Array;
    publicKeys: Uint8Array[];
    tweaks?: Tweak[];
    msg: Uint8Array;
    rand?: Uint8Array;
  }): { publicNonce: Uint8Array };
  // TODO: Discuss with HSM team the generation of all the nonces and any
  // potential scaling concerns (3x the total cost of schnorr signing)
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
   * @param compress [default=true] if false, uncompress the point
   * @returns The point, compressed if compress is true, or uncompressed if false.
   */
  pointCompress(p: Uint8Array, compress?: boolean): Uint8Array;

  /**
   * Adds one value to another, mod n.
   *
   * @param a An addend, 0 <= a < n
   * @param b An addend, 0 <= b < n
   * @returns The sum, 0 <= sum < n
   */
  scalarAdd(a: Uint8Array, b: Uint8Array): Uint8Array;

  /**
   * Multiply one value by another, mod n.
   *
   * @param a The multiplicand, 0 <= a < n
   * @param b The multiplier, 0 <= b < n
   * @returns The product, 0 <= product < n
   */
  scalarMultiply(a: Uint8Array, b: Uint8Array): Uint8Array;

  /**
   * Negates a value, mod n.
   *
   * @param a The value to negate, 0 <= a < n
   * @returns The negated value, 0 <= negated < n
   */
  scalarNegate(a: Uint8Array): Uint8Array;

  /**
   * @param a The value to reduce
   * @returns a mod n
   */
  scalarMod(a: Uint8Array): Uint8Array;

  /**
   * @param s A buffer to check against the curve order
   * @returns true if s is a 32-byte array 0 <= s < n
   */
  isScalar(s: Uint8Array): boolean;

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

export type Tweak = TypedTweak | Uint8Array;
export interface TypedTweak {
  tweak: Uint8Array;
  xOnly?: boolean;
}

export interface KeyGenContext {
  aggPublicKey: Uint8Array; // a point on the curve
  gacc: Uint8Array; // accumulated negation factor from X-only tweaking
  tacc: Uint8Array; // 32-byte accumulated tweak (mod n)
}

interface SessionValues extends KeyGenContext {
  coefficient: Uint8Array; // 32-byte nonce coefficient (mod n)
  finalNonce: Uint8Array; // a point on the curve
  challenge: Uint8Array; // 32-byte challenge (mod n)
  publicKeys: Uint8Array[]; // individual public keys in compressed DER format
}

export interface SessionKey {
  publicKey: Uint8Array;
  aggNonce: Uint8Array;
  msg: Uint8Array;
}

const TAGS = {
  challenge: 'BIP0340/challenge',
  keyagg_list: 'KeyAgg list',
  keyagg_coef: 'KeyAgg coefficient',
  musig_aux: 'MuSig/aux',
  musig_nonce: 'MuSig/nonce',
  musig_deterministic_nonce: 'MuSig/deterministic/nonce',
  musig_noncecoef: 'MuSig/noncecoef',
} as const;

/**
 * Compares two 32-byte Uint8Arrays in byte order.
 * @returns < 0, 0, > 0 if a is < b, === b or > b respectively
 */
function compare32b(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== 32 || b.length !== 32) throw new Error('Invalid array');
  const aD = new DataView(a.buffer, a.byteOffset, a.length);
  const bD = new DataView(b.buffer, b.byteOffset, b.length);
  for (let i = 0; i < 8; i++) {
    const cmp = aD.getUint32(i * 4) - bD.getUint32(i * 4);
    if (cmp !== 0) return cmp;
  }
  return 0;
}

/**
 * Compares two 33-byte Uint8Arrays in byte order.
 * @returns < 0, 0, > 0 if a is < b, === b or > b respectively
 */
function compare33b(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== 33 || b.length !== 33) throw new Error('Invalid array');
  const cmp = a[0] - b[0];
  if (cmp !== 0) return cmp;
  return compare32b(a.subarray(1), b.subarray(1));
}

declare const self: Record<string, any> | undefined;
const makeSessionId =
  typeof self === 'object' && (self.crypto || self.msCrypto)
    ? () => (self.crypto || self.msCrypto).getRandomValues(new Uint8Array(32)) // Browsers
    : () => require('crypto').randomBytes(32); // Node

// Caches values needed to compute key agg coefficients for an array of public keys
interface KeyAggCache {
  publicKeyHash: Uint8Array;
  secondPublicKey?: Uint8Array;
}
const _keyAggCache = new WeakMap<Uint8Array[], KeyAggCache>();

// Caches coefficients associated with an array of public keys
const _coefCache = new WeakMap<Uint8Array[], Map<Uint8Array, Uint8Array>>();

// Caches secret nonces. We do this internally to help users ensure that they
// do not reuse a secret nonce.
const _nonceCache = new WeakMap<Uint8Array, Uint8Array>();

// Caches signing sessions. We do this internally to help users ensure that
// these session values were generated on the signer, and are not accepted from
// an untrusted third party.
const _sessionCache = new WeakMap<SessionKey, SessionValues>();

export function MuSigFactory(ecc: Crypto): MuSig {
  const CPOINT_INF = new Uint8Array(33);
  const SCALAR_0 = new Uint8Array(32);
  const SCALAR_1 = new Uint8Array(32);
  SCALAR_1[31] = 1;
  const SCALAR_MINUS_1 = ecc.scalarNegate(SCALAR_1);

  function keyAggCoeff(publicKeys: Uint8Array[], publicKey: Uint8Array): Uint8Array {
    let coefCache = _coefCache.get(publicKeys);
    if (coefCache === undefined) {
      coefCache = new Map<Uint8Array, Uint8Array>();
      _coefCache.set(publicKeys, coefCache);
    }
    let coefficient = coefCache.get(publicKey);
    if (coefficient) return coefficient;

    coefficient = SCALAR_1;
    let secondPublicKey;
    let publicKeyHash;
    let keyAggCache = _keyAggCache.get(publicKeys);
    if (keyAggCache === undefined) {
      // Index of the first occurrence of the second unique public key.
      const pkIdx2 = publicKeys.findIndex((pk) => compare33b(pk, publicKeys[0]) !== 0);
      secondPublicKey = publicKeys[pkIdx2]; // undefined if pkIdx2 === -1
      publicKeyHash = ecc.taggedHash(TAGS.keyagg_list, ...publicKeys);
      keyAggCache = { publicKeyHash, secondPublicKey };
      _keyAggCache.set(publicKeys, keyAggCache);
    } else {
      ({ publicKeyHash, secondPublicKey } = keyAggCache);
    }
    if (secondPublicKey === undefined || compare33b(publicKey, secondPublicKey) !== 0)
      coefficient = ecc.taggedHash(TAGS.keyagg_coef, publicKeyHash, publicKey);
    coefCache.set(publicKey, coefficient);
    return coefficient;
  }

  function addTweak(ctx: KeyGenContext, t: Tweak): KeyGenContext {
    const tweak = 'tweak' in t ? t : { tweak: t };
    if (!ecc.isScalar(tweak.tweak))
      throw new TypeError('Expected tweak to be a valid scalar with curve order');
    let { gacc, tacc } = ctx;
    let aggPublicKey: Uint8Array | null = ctx.aggPublicKey;

    if (!ecc.hasEvenY(aggPublicKey) && tweak.xOnly) {
      // g = -1
      gacc = ecc.scalarNegate(gacc); // g * gacc mod n
      tacc = ecc.scalarNegate(tacc); // g * tacc mod n
      aggPublicKey = ecc.pointNegate(aggPublicKey); // g * Q
    }
    aggPublicKey = ecc.pointAddTweak(aggPublicKey, tweak.tweak, false); // g * Q + t * G
    if (aggPublicKey === null) throw new Error('Unexpected point at infinity during tweaking');
    tacc = ecc.scalarAdd(tweak.tweak, tacc); // t + g * tacc mod n

    return { aggPublicKey, gacc, tacc };
  }

  function keyAgg(publicKeys: Uint8Array[], ...tweaks: Tweak[]): KeyGenContext {
    checkArgs({ publicKeys });
    const multipliedPublicKeys = publicKeys.map((publicKey) => {
      const coefficient = keyAggCoeff(publicKeys, publicKey);
      let multipliedPublicKey: Uint8Array | null;
      if (compare32b(coefficient, SCALAR_1) === 0) {
        multipliedPublicKey = publicKey;
      } else {
        multipliedPublicKey = ecc.pointMultiplyUnsafe(publicKey, coefficient, false);
      }
      if (multipliedPublicKey === null) throw new Error('Point at infinity during aggregation');
      return multipliedPublicKey;
    });

    const aggPublicKey = multipliedPublicKeys.reduce((a, b) => {
      const next = ecc.pointAdd(a, b, false);
      if (next === null) throw new Error('Point at infinity during aggregation');
      return next;
    });

    return tweaks.reduce((ctx, tweak) => addTweak(ctx, tweak), {
      aggPublicKey,
      gacc: SCALAR_1,
      tacc: SCALAR_0,
    });
  }

  function getSessionValues(sessionKey: SessionKey): SessionValues {
    const sessionValues = _sessionCache.get(sessionKey);
    if (!sessionValues) throw new Error('Invalid session key, please call `startSigningSession`');
    return sessionValues;
  }

  function nonceAgg(publicNonces: Uint8Array[]): Uint8Array {
    checkArgs({ publicNonces });

    const aggNonces: Array<Uint8Array | null> = [
      publicNonces[0].subarray(0, 33),
      publicNonces[0].subarray(33),
    ];
    for (let i = 1; i < publicNonces.length; i++) {
      if (aggNonces[0] !== null)
        aggNonces[0] = ecc.pointAdd(aggNonces[0], publicNonces[i].subarray(0, 33), false);
      if (aggNonces[1] !== null)
        aggNonces[1] = ecc.pointAdd(aggNonces[1], publicNonces[i].subarray(33), false);
    }
    const aggNonce = new Uint8Array(66);
    if (aggNonces[0] !== null) aggNonce.set(ecc.pointCompress(aggNonces[0]), 0);
    if (aggNonces[1] !== null) aggNonce.set(ecc.pointCompress(aggNonces[1]), 33);
    return aggNonce;
  }

  function startSigningSessionInner(
    aggNonce: Uint8Array,
    msg: Uint8Array,
    publicKeys: Uint8Array[],
    ctx: KeyGenContext
  ): SessionKey {
    const pubKeyX = ecc.pointX(ctx.aggPublicKey);

    const coefficient = ecc.taggedHash(TAGS.musig_noncecoef, aggNonce, pubKeyX, msg);

    const aggNonces = [aggNonce.subarray(0, 33), aggNonce.subarray(33)];

    // This is kinda ugly, but crypto.pointAdd doesn't work on 0-coded infinity
    let r: Uint8Array | null = null;
    if (compare33b(aggNonces[1], CPOINT_INF) !== 0 && compare33b(aggNonces[0], CPOINT_INF) !== 0) {
      r = ecc.pointMultiplyAndAddUnsafe(aggNonces[1], coefficient, aggNonces[0], false);
    } else if (compare33b(aggNonces[0], CPOINT_INF) !== 0) {
      r = ecc.pointCompress(aggNonces[0], false);
    } else if (compare33b(aggNonces[1], CPOINT_INF) !== 0) {
      r = ecc.pointMultiplyUnsafe(aggNonces[1], coefficient, false);
    }
    if (r === null) r = ecc.getPublicKey(SCALAR_1, false);
    if (r === null) throw new Error('Failed to get G');

    const challenge = ecc.scalarMod(ecc.taggedHash(TAGS.challenge, ecc.pointX(r), pubKeyX, msg));

    const key = { publicKey: ctx.aggPublicKey, aggNonce, msg };
    _sessionCache.set(key, { ...ctx, coefficient, challenge, finalNonce: r, publicKeys });
    return key;
  }

  function partialVerifyInner({
    sig,
    publicKey,
    publicNonces,
    sessionKey,
  }: {
    sig: Uint8Array;
    publicKey: Uint8Array;
    publicNonces: [Uint8Array, Uint8Array];
    sessionKey: SessionKey;
  }): boolean {
    const { msg } = sessionKey;
    const { aggPublicKey, gacc, challenge, coefficient, finalNonce, publicKeys } =
      getSessionValues(sessionKey);

    const rePrime = ecc.pointMultiplyAndAddUnsafe(
      publicNonces[1],
      coefficient,
      publicNonces[0],
      false
    );
    if (rePrime === null) throw new Error('Unexpected public nonce at infinity');
    const re = ecc.hasEvenY(finalNonce) ? rePrime : ecc.pointNegate(rePrime);

    const a = keyAggCoeff(publicKeys, publicKey);

    const g = ecc.hasEvenY(aggPublicKey) ? gacc : ecc.scalarNegate(gacc);

    const ea = ecc.scalarMultiply(challenge, a);
    const eag = ecc.scalarMultiply(ea, g);
    const ver = ecc.pointMultiplyAndAddUnsafe(publicKey, eag, re, true);
    if (ver === null) throw new Error('Unexpected verification point at infinity');

    const sG = ecc.getPublicKey(sig, true);
    if (sG === null) throw new Error('Unexpected signature point at infinity');

    return compare33b(ver, sG) === 0;
  }

  function partialSignInner({
    secretKey,
    publicKey,
    secretNonces,
    sessionKey,
  }: {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
    secretNonces: [Uint8Array, Uint8Array];
    sessionKey: SessionKey;
  }): Uint8Array {
    const { msg } = sessionKey;
    const { aggPublicKey, gacc, challenge, coefficient, finalNonce, publicKeys } =
      getSessionValues(sessionKey);

    const [k1, k2] = secretNonces.map((k) => (ecc.hasEvenY(finalNonce) ? k : ecc.scalarNegate(k)));

    const a = keyAggCoeff(publicKeys, publicKey);

    const g = ecc.hasEvenY(aggPublicKey) ? gacc : ecc.scalarNegate(gacc);
    const d = ecc.scalarMultiply(g, secretKey);

    const bk2 = ecc.scalarMultiply(coefficient, k2);
    const k1bk2 = ecc.scalarAdd(k1, bk2);

    const ea = ecc.scalarMultiply(challenge, a);
    const ead = ecc.scalarMultiply(ea, d);

    const sig = ecc.scalarAdd(k1bk2, ead);

    return sig;
  }

  function partialSign({
    secretKey,
    publicNonce,
    sessionKey,
    verify = true,
  }: {
    secretKey: Uint8Array;
    publicNonce: Uint8Array;
    sessionKey: SessionKey;
    verify: boolean;
  }): Uint8Array {
    checkArgs({ publicNonce, secretKey });

    const secretNonce = _nonceCache.get(publicNonce);
    if (secretNonce === undefined)
      throw new Error('No secret nonce found for specified public nonce');
    _nonceCache.delete(publicNonce);

    const publicKey = ecc.getPublicKey(secretKey, true);
    if (publicKey === null) throw new Error('Invalid secret key, no corresponding public key');
    if (compare33b(publicKey, secretNonce.subarray(64)) !== 0)
      throw new Error('Secret nonce pubkey mismatch');
    const secretNonces: [Uint8Array, Uint8Array] = [
      secretNonce.subarray(0, 32),
      secretNonce.subarray(32, 64),
    ];
    const sig = partialSignInner({
      secretKey,
      publicKey,
      secretNonces,
      sessionKey,
    });

    if (verify) {
      const publicNonces: [Uint8Array, Uint8Array] = [
        publicNonce.subarray(0, 33),
        publicNonce.subarray(33),
      ];
      const valid = partialVerifyInner({
        sig,
        publicKey,
        publicNonces,
        sessionKey,
      });
      if (!valid) throw new Error('Partial signature failed verification');
    }
    return sig;
  }

  interface DeterministicSignArgsBase {
    secretKey: Uint8Array;
    aggOtherNonce: Uint8Array;
    publicKeys: Uint8Array[];
    tweaks?: Tweak[];
    msg: Uint8Array;
    rand?: Uint8Array;
  }
  interface DeterministicSignArgs extends DeterministicSignArgsBase {
    verify?: boolean;
    nonceOnly?: boolean;
  }
  interface DeterministicSignArgsSign extends DeterministicSignArgsBase {
    verify: boolean;
  }
  interface DeterministicSignArgsNonceOnly extends DeterministicSignArgsBase {
    nonceOnly: true;
  }
  function deterministicSign(args: DeterministicSignArgsSign): {
    sig: Uint8Array;
    sessionKey: SessionKey;
    publicNonce: Uint8Array;
  };
  function deterministicSign(args: DeterministicSignArgsNonceOnly): { publicNonce: Uint8Array };
  function deterministicSign({
    secretKey,
    aggOtherNonce,
    publicKeys,
    tweaks = [],
    msg,
    rand,
    verify = true,
    nonceOnly = false,
  }: DeterministicSignArgs): {
    sig?: Uint8Array;
    sessionKey?: SessionKey;
    publicNonce: Uint8Array;
  } {
    // No need to check msg, its max size is larger than JS typed array limit
    checkArgs({ rand, secretKey, aggOtherNonce });
    const publicKey = ecc.getPublicKey(secretKey, true);
    if (publicKey === null) throw new Error('Secret key has no corresponding public key');

    let secretKeyPrime;
    if (rand !== undefined) {
      secretKeyPrime = ecc.taggedHash(TAGS.musig_aux, rand);
      for (let i = 0; i < 32; i++) {
        secretKeyPrime[i] = secretKeyPrime[i] ^ secretKey[i];
      }
    } else {
      secretKeyPrime = secretKey;
    }
    const ctx = keyAgg(publicKeys, ...tweaks);
    const aggPublicKey = ecc.pointX(ctx.aggPublicKey);

    const mLength = new Uint8Array(8);
    new DataView(mLength.buffer).setBigUint64(0, BigInt(msg.length));

    const secretNonce = new Uint8Array(97);
    const publicNonce = new Uint8Array(66);
    for (let i = 0; i < 2; i++) {
      const kH = ecc.taggedHash(
        TAGS.musig_deterministic_nonce,
        ...[secretKeyPrime, aggOtherNonce, aggPublicKey, mLength, msg, Uint8Array.of(i)]
      );
      const k = ecc.scalarMod(kH);
      if (compare32b(SCALAR_0, k) === 0) throw new Error('0 secret nonce');
      const pub = ecc.getPublicKey(k, true);
      if (pub === null) throw new Error('Secret nonce has no corresponding public nonce');

      secretNonce.set(k, i * 32);
      publicNonce.set(pub, i * 33);
    }
    secretNonce.set(publicKey, 64);

    if (nonceOnly) return { publicNonce };

    _nonceCache.set(publicNonce, secretNonce);
    const aggNonce = nonceAgg([aggOtherNonce, publicNonce]);
    const sessionKey = startSigningSessionInner(aggNonce, msg, publicKeys, ctx);
    const sig = partialSign({
      secretKey,
      publicNonce,
      sessionKey,
      verify,
    });

    return { sig, sessionKey, publicNonce };
  }

  // TODO: Improve arg checking now that we have startSigningSession
  const pubKeyArgs = ['publicKey', 'publicKeys'] as const;
  const scalarArgs = ['tweak', 'sig', 'sigs', 'tacc', 'gacc'] as const;
  const otherArgs32b = ['xOnlyPublicKey', 'rand', 'sessionId'] as const;
  const args32b = ['secretKey', ...scalarArgs, ...otherArgs32b] as const;
  const pubNonceArgs = [
    'publicNonce',
    'publicNonces',
    'aggNonce',
    'aggOtherNonce',
    'finalNonce',
  ] as const;
  const otherArgs = ['aggPublicKey', 'secretNonce'] as const;
  type ArgName =
    | typeof pubKeyArgs[number]
    | typeof args32b[number]
    | typeof pubNonceArgs[number]
    | typeof otherArgs[number];
  type Args = { [A in ArgName]?: Uint8Array | Uint8Array[] };

  const argLengths = new Map<string, number>();
  args32b.forEach((a) => argLengths.set(a, 32));
  pubKeyArgs.forEach((a) => argLengths.set(a, 33));
  pubNonceArgs.forEach((a) => argLengths.set(a, 66));
  argLengths.set('secretNonce', 97);
  argLengths.set('aggPublicKey', 65);
  const scalarNames = new Set<string>();
  scalarArgs.forEach((n) => scalarNames.add(n));

  function checkArgs(args: Args): void {
    for (let [name, values] of Object.entries(args)) {
      if (values === undefined) continue;
      values = Array.isArray(values) ? values : [values];
      if (values.length === 0) throw new TypeError(`0-length ${name}s not supported`);
      for (const value of values) {
        if (argLengths.get(name) !== value.length)
          throw new TypeError(`Invalid ${name} length (${value.length})`);
        if (name === 'secretKey') {
          if (!ecc.isSecret(value)) throw new TypeError(`Invalid secretKey`);
        } else if (name === 'secretNonce') {
          for (let i = 0; i < 64; i += 32)
            if (!ecc.isSecret(value.subarray(i, i + 32)))
              throw new TypeError(`Invalid secretNonce`);
        } else if (scalarNames.has(name)) {
          for (let i = 0; i < value.length; i += 32)
            if (!ecc.isScalar(value.subarray(i, i + 32))) throw new TypeError(`Invalid ${name}`);
        }
        // No need for a public key x-to-curve check. They're liftX'd for use any way.
      }
    }
  }

  return {
    getXOnlyPubkey: (ctx: KeyGenContext | SessionKey): Uint8Array => {
      if ('aggPublicKey' in ctx) return ecc.pointX(ctx.aggPublicKey);
      return ecc.pointX(getSessionValues(ctx).aggPublicKey);
    },
    getPlainPubkey: (ctx: KeyGenContext | SessionKey): Uint8Array => {
      if ('aggPublicKey' in ctx) return ecc.pointCompress(ctx.aggPublicKey);
      return ecc.pointCompress(getSessionValues(ctx).aggPublicKey);
    },
    keySort: (publicKeys: Uint8Array[]): Uint8Array[] => {
      checkArgs({ publicKeys });
      // do not modify the original array
      return [...publicKeys].sort((a, b) => compare33b(a, b));
    },
    keyAgg,
    addTweaks: (ctx: KeyGenContext, ...tweaks: Tweak[]): KeyGenContext => {
      checkArgs(ctx);
      return tweaks.reduce((c, tweak) => addTweak(c, tweak), ctx);
    },

    nonceGen: ({
      sessionId = makeSessionId(),
      secretKey,
      publicKey,
      xOnlyPublicKey,
      msg,
      extraInput,
    }: {
      sessionId: Uint8Array;
      secretKey?: Uint8Array;
      publicKey: Uint8Array;
      xOnlyPublicKey?: Uint8Array;
      msg?: Uint8Array;
      extraInput?: Uint8Array;
    }): Uint8Array => {
      if (extraInput !== undefined && extraInput.length > Math.pow(2, 32) - 1)
        throw new TypeError('extraInput is limited to 2^32-1 bytes');
      // No need to check msg, its max size is larger than JS typed array limit
      checkArgs({ sessionId, secretKey, publicKey, xOnlyPublicKey });
      let rand: Uint8Array;
      if (secretKey !== undefined) {
        rand = ecc.taggedHash(TAGS.musig_aux, sessionId);
        for (let i = 0; i < 32; i++) {
          rand[i] = rand[i] ^ secretKey[i];
        }
      } else {
        rand = sessionId;
      }

      if (xOnlyPublicKey === undefined) xOnlyPublicKey = new Uint8Array();

      const mPrefixed = [Uint8Array.of(0)];
      if (msg !== undefined) {
        mPrefixed[0][0] = 1;
        mPrefixed.push(new Uint8Array(8));
        new DataView(mPrefixed[1].buffer).setBigUint64(0, BigInt(msg.length));
        mPrefixed.push(msg);
      }

      if (extraInput === undefined) extraInput = new Uint8Array();
      const eLength = new Uint8Array(4);
      new DataView(eLength.buffer).setUint32(0, extraInput.length);

      const secretNonce = new Uint8Array(97);
      const publicNonce = new Uint8Array(66);
      for (let i = 0; i < 2; i++) {
        const kH = ecc.taggedHash(
          TAGS.musig_nonce,
          rand,
          Uint8Array.of(publicKey.length),
          publicKey,
          Uint8Array.of(xOnlyPublicKey.length),
          xOnlyPublicKey,
          ...mPrefixed,
          eLength,
          extraInput,
          Uint8Array.of(i)
        );
        const k = ecc.scalarMod(kH);
        if (compare32b(SCALAR_0, k) === 0) throw new Error('0 secret nonce');
        const pub = ecc.getPublicKey(k, true);
        if (pub === null) throw new Error('Secret nonce has no corresponding public nonce');

        secretNonce.set(k, i * 32);
        publicNonce.set(pub, i * 33);
      }
      secretNonce.set(publicKey, 64);
      _nonceCache.set(publicNonce, secretNonce);
      return publicNonce;
    },

    addExternalNonce: (publicNonce: Uint8Array, secretNonce: Uint8Array): void => {
      checkArgs({ publicNonce, secretNonce });
      _nonceCache.set(publicNonce, secretNonce);
    },

    deterministicNonceGen: (args: DeterministicSignArgsBase): { publicNonce: Uint8Array } =>
      deterministicSign({ ...args, nonceOnly: true }),

    deterministicSign,

    nonceAgg,

    startSigningSession: (
      aggNonce: Uint8Array,
      msg: Uint8Array,
      publicKeys: Uint8Array[],
      ...tweaks: Tweak[]
    ): SessionKey => {
      checkArgs({ aggNonce });
      const ctx = keyAgg(publicKeys, ...tweaks);
      return startSigningSessionInner(aggNonce, msg, publicKeys, ctx);
    },

    partialSign,

    partialVerify: ({
      sig,
      publicKey,
      publicNonce,
      sessionKey,
    }: {
      sig: Uint8Array;
      publicKey: Uint8Array;
      publicNonce: Uint8Array;
      sessionKey: SessionKey;
    }): boolean => {
      checkArgs({ sig, publicKey, publicNonce });

      const publicNonces: [Uint8Array, Uint8Array] = [
        publicNonce.subarray(0, 33),
        publicNonce.subarray(33),
      ];

      const valid = partialVerifyInner({
        sig,
        publicKey,
        publicNonces,
        sessionKey,
      });
      return valid;
    },

    signAgg: (sigs: Uint8Array[], sessionKey: SessionKey): Uint8Array => {
      checkArgs({ sigs });

      const { aggPublicKey, tacc, challenge, finalNonce } = getSessionValues(sessionKey);
      let sPart: Uint8Array = ecc.scalarMultiply(challenge, tacc);
      if (!ecc.hasEvenY(aggPublicKey)) {
        sPart = ecc.scalarNegate(sPart);
      }
      const aggS = sigs.reduce((a, b) => ecc.scalarAdd(a, b), sPart);
      const sig = new Uint8Array(64);
      sig.set(ecc.pointX(finalNonce), 0);
      sig.set(aggS, 32);
      return sig;
    },
  };
}
