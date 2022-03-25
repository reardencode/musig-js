'use strict';
/*! musig-js - MIT License (c) 2022 Brandon Black */
Object.defineProperty(exports, '__esModule', { value: true });
exports.MuSigFactory = void 0;
const TAGS = {
  challenge: 'BIP0340/challenge',
  keyagg_list: 'KeyAgg list',
  keyagg_coef: 'KeyAgg coefficient',
  musig_nonce: 'MuSig/nonce',
  musig_noncecoef: 'MuSig/noncecoef',
};
const U8A0 = new Uint8Array(32);
function compare32b(a, b) {
  if (a.length !== 32 || b.length !== 32) throw new Error('Can only compare 32 byte arrays');
  const aD = new DataView(a.buffer, a.byteOffset, a.length);
  const bD = new DataView(b.buffer, b.byteOffset, b.length);
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
        if (coef === undefined) return evenPublicKeys[i];
        const spk = ecc.pointMultiply(evenPublicKeys[i], coef, false);
        if (!spk) throw new Error('Point at infinity during aggregation');
        return spk;
      });
      let publicKey = shiftedPublicKeys[0];
      for (let i = 1; i < shiftedPublicKeys.length; i++) {
        publicKey = ecc.pointAdd(publicKey, shiftedPublicKeys[i], false);
        if (!publicKey) throw new Error('Point at infinty during aggregation');
      }
      return cache.copyWith(publicKey);
    }
    assertValidity() {
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
    coefficient(publicKey) {
      if (compare32b(publicKey, this.secondPublicKeyX) === 0) return undefined;
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
        if (!ecc.hasEvenY(publicKey) && tweaksXOnly[i]) {
          parity = !parity;
          tweak = ecc.secretNegate(tweak);
          publicKey = ecc.pointNegate(publicKey);
        }
        publicKey = ecc.pointAddTweak(publicKey, tweaks[i], false);
        if (!publicKey) throw new Error('Tweak failed');
        tweak = ecc.secretAdd(tweak, tweaks[i]);
      }
      return this.copyWith(publicKey, parity, tweak);
    }
    dump() {
      const rest = new Uint8Array(130);
      rest.set(this.publicKey, 0);
      rest.set(this.secondPublicKeyX, 65);
      rest[97] = this.parity ? 1 : 0;
      rest.set(this.tweak, 98);
      return { base: this.publicKeyHash, rest };
    }
    static load(session) {
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
    toAggregatePublicKey() {
      return {
        parity: ecc.hasEvenY(this.publicKey) ? 0 : 1,
        publicKey: ecc.pointX(this.publicKey),
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
        session.subarray(1, 33),
        session.subarray(33, 65),
        session.subarray(65, 97),
        session.subarray(97)
      );
    }
    assertValidity() {
      if (
        !ecc.isXOnlyPoint(this.finalNonceX) ||
        !ecc.isSecret(this.coefficient) ||
        !ecc.isSecret(this.challenge) ||
        (compare32b(this.sPart, U8A0) !== 0 && !ecc.isSecret(this.sPart))
      )
        throw new Error('Invalid ProcessedNonce');
    }
    dump() {
      const session = new Uint8Array(129);
      session[0] = this.finalNonceHasOddY ? 1 : 0;
      session.set(this.finalNonceX, 1);
      session.set(this.coefficient, 33);
      session.set(this.challenge, 65);
      session.set(this.sPart, 97);
      return session;
    }
  }
  function normalizeNonceArg(p) {
    if (!p) return [Uint8Array.of(0)];
    if (p.length !== 32) throw new Error('Expected 32 bytes');
    return [Uint8Array.of(32), p];
  }
  function nonceProcess(aggNonce, message, cache) {
    const pubKeyX = ecc.pointX(cache.publicKey);
    const coefficient = ecc.taggedHash(TAGS.musig_noncecoef, aggNonce, pubKeyX, message);
    const aggNonces = [aggNonce.subarray(0, 33), aggNonce.subarray(33)];
    const bK2 = ecc.pointMultiply(aggNonces[1], coefficient, false);
    if (!bK2) throw new Error('Nonce part at infinity');
    const finalNonce = ecc.pointAdd(aggNonces[0], bK2, false);
    if (!finalNonce) throw new Error('Unexpected final nonce at infinity');
    const finalNonceX = ecc.pointX(finalNonce);
    const challenge = ecc.secretMod(ecc.taggedHash(TAGS.challenge, finalNonceX, pubKeyX, message));
    let sPart = U8A0;
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
  function partialVerifyInner({ sig, publicKeyX, publicNonces, cache, processedNonce }) {
    const bK2 = ecc.pointMultiply(publicNonces[1], processedNonce.coefficient, false);
    if (!bK2) throw new Error('Nonce part at infinity');
    let rj = ecc.pointAdd(publicNonces[0], bK2, false);
    if (!rj) throw new Error('Unexpected public nonce at infinity');
    if (processedNonce.finalNonceHasOddY) rj = ecc.pointNegate(rj);
    let publicKey = ecc.liftX(publicKeyX);
    if (!publicKey) throw new Error('Invalid verification key');
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
    message,
    secretKey,
    publicKey,
    secretNonces,
    cache,
    processedNonce,
  }) {
    const bk2 = ecc.secretMultiply(processedNonce.coefficient, secretNonces[1]);
    let k1bk2 = ecc.secretAdd(secretNonces[0], bk2);
    if (processedNonce.finalNonceHasOddY) k1bk2 = ecc.secretNegate(k1bk2);
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
    keyAgg: (publicKeys, opts = {}) => {
      let cache = KeyAggCache.fromPublicKeys(publicKeys, opts.sort);
      if (opts.tweaks !== undefined) cache = cache.addTweaks(opts.tweaks, opts.tweaksXOnly);
      return cache.toAggregatePublicKey();
    },
    addTweaks: (session, tweaks, tweaksXOnly) => {
      let cache = KeyAggCache.load(session);
      cache = cache.addTweaks(tweaks, tweaksXOnly);
      return cache.toAggregatePublicKey();
    },
    nonceGen: ({ sessionId, secretKey, message, aggregatePublicKey, extraInput }) => {
      const seed = ecc.taggedHash(
        TAGS.musig_nonce,
        ...[
          sessionId,
          ...normalizeNonceArg(secretKey),
          ...normalizeNonceArg(message),
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
    nonceAgg: (nonces) => {
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
    partialSign: ({ message, secretKey, nonce, aggNonce, session }) => {
      const publicKey = ecc.getPublicKey(secretKey, false);
      if (!publicKey) throw new Error('Invalid secret key, no corresponding public key');
      const secretNonces = [nonce.secretNonce.subarray(0, 32), nonce.secretNonce.subarray(32)];
      const cache = KeyAggCache.load(session);
      const processedNonce = nonceProcess(aggNonce, message, cache);
      const sig = partialSignInner({
        message,
        secretKey,
        publicKey,
        secretNonces,
        cache,
        processedNonce,
      });
      let publicNonces;
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
      return { sig, session: processedNonce.dump() };
    },
    partialVerify: ({ sig, message, publicKey, publicNonce, aggNonce, keyAggSession, session }) => {
      const publicNonces = [publicNonce.subarray(0, 33), publicNonce.subarray(33)];
      const cache = KeyAggCache.load(keyAggSession);
      const processedNonce = session
        ? ProcessedNonce.load(session)
        : nonceProcess(aggNonce, message, cache);
      const valid = partialVerifyInner({
        sig,
        publicKeyX: publicKey,
        publicNonces,
        cache,
        processedNonce,
      });
      return valid && { session: processedNonce.dump() };
    },
    signAgg: (sigs, session) => {
      const processedNonce = ProcessedNonce.load(session);
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
exports.MuSigFactory = MuSigFactory;
