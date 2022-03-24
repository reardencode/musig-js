'use strict';
/*! musig-js - MIT License (c) 2022 Brandon Black */
Object.defineProperty(exports, '__esModule', { value: true });
exports.MuSigFactory = void 0;
const buffer_1 = require('buffer');
const TAGS = {
  challenge: 'BIP0340/challenge',
  keyagg_list: 'KeyAgg list',
  keyagg_coef: 'KeyAgg coefficient',
  musig_nonce: 'MuSig/nonce',
  musig_noncecoef: 'MuSig/noncecoef',
};
const U8A0 = buffer_1.Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);
const U8A1 = buffer_1.Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex'
);
function pointX(p) {
  if (p.length === 32) return p;
  if (p.length === 33) return p.subarray(1);
  if (p.length === 65) return p.subarray(1, 33);
  throw new Error('Wrong length to be a point');
}
function hasEvenY(p) {
  if (p.length === 33) return p[0] % 2 === 0;
  if (p.length === 65) return p[32] % 2 === 0;
  throw new Error('Wrong length to be a point');
}
function compare32b(a, b) {
  if (a.length !== 32 || b.length !== 32) throw new Error('Can only compare 32 byte arrays');
  const aD = new DataView(a.buffer);
  const bD = new DataView(b.buffer);
  for (let i = 0; i < 8; i++) {
    const cmp = aD.getUint32(i * 4) - bD.getUint32(i * 4);
    if (cmp !== 0) return cmp;
  }
  return 0;
}
function MuSigFactory(ecc) {
  const _coefCache = new WeakMap();
  class KeyAggCache {
    constructor(
      publicKeyHash,
      secondPublicKeyX = U8A0,
      publicKey = new Uint8Array(65),
      parity = false,
      tweak = U8A0,
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
    static fromPublicKeys(publicKeys, sort = true) {
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
    assertValidity() {
      if (
        !ecc.isPoint(this.publicKey) ||
        this.publicKeyHash.length !== 32 ||
        (compare32b(this.secondPublicKeyX, U8A0) !== 0 &&
          !ecc.isXOnlyPoint(this.secondPublicKeyX)) ||
        (this.tweak !== U8A0 && !ecc.isSecret(this.tweak))
      )
        throw new Error('Invalid KeyAggCache');
    }
    coefficient(publicKey) {
      if (compare32b(publicKey, this.secondPublicKeyX) === 0) return U8A1;
      const key = Buffer.from(publicKey).toString('hex');
      let coef = this._coefCache.get(key);
      if (coef === undefined) {
        coef = ecc.taggedHash(TAGS.keyagg_coef, this.publicKeyHash, publicKey);
        this._coefCache.set(key, coef);
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
          tweak = ecc.secretNegate(tweak);
          publicKey = ecc.pointNegate(publicKey);
        }
        publicKey = ecc.pointAddTweak(publicKey, tweaks[i]);
        if (!publicKey) throw new Error('Tweak failed');
        tweak = ecc.secretAdd(tweak, tweaks[i]);
      }
      return this.copyWith(publicKey, parity, tweak);
    }
    dump() {
      return {
        base: this.publicKeyHash,
        rest: buffer_1.Buffer.concat([
          this.secondPublicKeyX,
          this.publicKey,
          Uint8Array.of(this.parity ? 1 : 0),
          this.tweak,
        ]),
      };
    }
    static load(session) {
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
    toAggregatePublicKey() {
      return {
        parity: hasEvenY(this.publicKey) ? 0 : 1,
        publicKey: pointX(this.publicKey),
        session: this.dump(),
      };
    }
  }
  class ProcessedNonce {
    constructor(finalNonceHasOddY, finalNonceX, coefficient, challenge, sPart) {
      this.finalNonceHasOddY = finalNonceHasOddY;
      this.finalNonceX = finalNonceX;
      this.coefficient = coefficient;
      this.challenge = challenge;
      this.sPart = sPart;
      this.assertValidity();
    }
    static load(session) {
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
    assertValidity() {
      if (
        !ecc.isXOnlyPoint(this.finalNonceX) ||
        !ecc.isSecret(this.coefficient) ||
        !ecc.isSecret(this.challenge) ||
        (compare32b(U8A0, this.sPart) !== 0 && !ecc.isSecret(this.sPart))
      )
        throw new Error('Invalid ProcessedNonce');
    }
    dump() {
      return buffer_1.Buffer.concat([
        Uint8Array.of(this.finalNonceHasOddY ? 1 : 0),
        this.finalNonceX,
        this.coefficient,
        this.challenge,
        this.sPart,
      ]);
    }
  }
  function normalizeNonceArg(p) {
    if (!p) return [Uint8Array.of(0)];
    if (p.length !== 32) throw new Error('Expected 32 bytes');
    return [Uint8Array.of(32), p];
  }
  function nonceGen({ sessionId, secretKey, message, aggregatePublicKey, extraInput }) {
    const messages = [];
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
  function nonceAgg(nonces) {
    const noncePoints = nonces.map((nonce) => [nonce.subarray(0, 33), nonce.subarray(33)]);
    const aggNonces = noncePoints.reduce((prev, cur) => [
      ecc.pointAdd(prev[0], cur[0], false),
      ecc.pointAdd(prev[1], cur[1], false),
    ]);
    return Buffer.concat(aggNonces.map((nonce) => ecc.pointCompress(nonce, true)));
  }
  function nonceProcess(aggNonce, message, cache) {
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
    let sPart = U8A0;
    if (compare32b(cache.tweak, U8A0) !== 0) {
      sPart = ecc.secretMultiply(challenge, cache.tweak);
      if (!hasEvenY(cache.publicKey)) {
        sPart = ecc.secretNegate(sPart);
      }
    }
    return new ProcessedNonce(!hasEvenY(finalNonce), finalNonceX, coefficient, challenge, sPart);
  }
  function partialVerifyInner({ sig, publicKey, publicNonce, cache, processedNonce }) {
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
  function partialSign({ message, secretKey, nonce, aggNonce, session }) {
    const cache = KeyAggCache.load(session);
    const processedNonce = nonceProcess(aggNonce, message, cache);
    const secretNonces = [nonce.secretNonce.slice(0, 32), nonce.secretNonce.slice(32)];
    const publicNonce = nonce.publicNonce || [
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
  }) {
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
  function keyAgg(publicKeys, opts = {}) {
    let cache = KeyAggCache.fromPublicKeys(publicKeys, opts.sort);
    if (opts.tweaks !== undefined) cache = cache.addTweaks(opts.tweaks, opts.tweaksXOnly);
    return cache.toAggregatePublicKey();
  }
  function addTweaks(keyAggSession, tweaks, tweaksXOnly) {
    let cache = KeyAggCache.load(keyAggSession);
    cache = cache.addTweaks(tweaks, tweaksXOnly);
    return cache.toAggregatePublicKey();
  }
  function signAgg(sigs, session) {
    const processedNonce = ProcessedNonce.load(session);
    return buffer_1.Buffer.concat([
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
exports.MuSigFactory = MuSigFactory;
