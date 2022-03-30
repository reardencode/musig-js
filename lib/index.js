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
const U8A1 = new Uint8Array(32);
U8A1[31] = 1;
function compare32b(a, b) {
  const aD = new DataView(a.buffer, a.byteOffset, a.length);
  const bD = new DataView(b.buffer, b.byteOffset, b.length);
  for (let i = 0; i < 8; i++) {
    const cmp = aD.getUint32(i * 4) - bD.getUint32(i * 4);
    if (cmp !== 0) return cmp;
  }
  return 0;
}
function noneNull(keys) {
  return keys.every((pk) => pk !== null);
}
const _coefCache = new WeakMap();
function MuSigFactory(ecc) {
  function coef(publicKeyHash, publicKey, secondPublicKey) {
    let coefCache = _coefCache.get(publicKeyHash);
    if (coefCache === undefined) {
      coefCache = new Map();
      _coefCache.set(publicKeyHash, coefCache);
    }
    const key = Buffer.from(publicKey).toString('hex');
    let coefficient = coefCache.get(key);
    if (coefficient === undefined) {
      coefficient = U8A1;
      if (secondPublicKey === undefined || compare32b(publicKey, secondPublicKey) !== 0)
        coefficient = ecc.taggedHash(TAGS.keyagg_coef, publicKeyHash, publicKey);
      coefCache.set(key, coefficient);
    }
    return coefficient;
  }
  class KeyAggCache {
    constructor(publicKeyHash, publicKey, secondPublicKey, parity = false, tweak = U8A0) {
      this.publicKeyHash = publicKeyHash;
      this.publicKey = publicKey;
      this.secondPublicKey = secondPublicKey;
      this.parity = parity;
      this.tweak = tweak;
      if (
        !ecc.isPoint(publicKey) ||
        (secondPublicKey !== undefined && !ecc.isXOnlyPoint(secondPublicKey)) ||
        (compare32b(tweak, U8A0) !== 0 && !ecc.isSecret(tweak))
      )
        throw new Error('Invalid KeyAggCache');
    }
    copyWith(publicKey, parity, tweak) {
      const cache = new KeyAggCache(
        this.publicKeyHash,
        publicKey,
        this.secondPublicKey,
        parity,
        tweak
      );
      return cache;
    }
    static fromPublicKeys(publicKeys, sort = true) {
      if (sort) publicKeys.sort((a, b) => compare32b(a, b));
      const evenPublicKeys = publicKeys.map((pk) => ecc.liftX(pk));
      if (!noneNull(evenPublicKeys)) throw new Error('Invalid public key');
      const pkIdx2 = publicKeys.findIndex((pk) => compare32b(pk, publicKeys[0]) !== 0);
      const secondPublicKey = publicKeys[pkIdx2];
      const publicKeyHash = ecc.taggedHash(TAGS.keyagg_list, ...publicKeys);
      const initialIdx = pkIdx2 === -1 ? 0 : pkIdx2;
      let publicKey = evenPublicKeys[initialIdx];
      if (initialIdx === 0) {
        const coefficient = coef(publicKeyHash, publicKeys[initialIdx], secondPublicKey);
        publicKey = ecc.pointMultiplyUnsafe(publicKey, coefficient, false);
        if (publicKey === null) throw new Error('Point at infinity during aggregation');
      }
      for (let i = 0; i < publicKeys.length; i++) {
        if (i === initialIdx) continue;
        const coefficient = coef(publicKeyHash, publicKeys[i], secondPublicKey);
        publicKey = ecc.pointMultiplyAndAddUnsafe(evenPublicKeys[i], coefficient, publicKey, false);
        if (publicKey === null) throw new Error('Point at infinity during aggregation');
      }
      return new KeyAggCache(publicKeyHash, publicKey, secondPublicKey);
    }
    coefficient(publicKey) {
      return coef(this.publicKeyHash, publicKey, this.secondPublicKey);
    }
    addTweaks(tweaks, tweaksXOnly) {
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
        if (publicKey === null) throw new Error('Unexpected point at infinity during tweaking');
        tweak = ecc.secretAdd(tweak, tweaks[i]);
      }
      return this.copyWith(publicKey, parity, tweak);
    }
    dump() {
      const rest = new Uint8Array(130);
      rest.set(this.publicKey, 0);
      rest.set(this.secondPublicKey || U8A0, 65);
      rest[97] = this.parity ? 1 : 0;
      rest.set(this.tweak, 98);
      return { base: this.publicKeyHash, rest };
    }
    static load(session) {
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
    toAggregatePublicKey() {
      return {
        parity: ecc.hasEvenY(this.publicKey) ? 0 : 1,
        publicKey: ecc.pointX(this.publicKey),
        keyAggSession: this.dump(),
      };
    }
  }
  class ProcessedNonce {
    constructor(finalNonce, coefficient, challenge, sPart) {
      this.finalNonce = finalNonce;
      this.coefficient = coefficient;
      this.challenge = challenge;
      this.sPart = sPart;
      if (
        !ecc.isPoint(finalNonce) ||
        !ecc.isSecret(coefficient) ||
        !ecc.isSecret(challenge) ||
        (compare32b(sPart, U8A0) !== 0 && !ecc.isSecret(sPart))
      )
        throw new Error('Invalid ProcessedNonce');
    }
    static process(aggNonce, msg, cache) {
      const pubKeyX = ecc.pointX(cache.publicKey);
      const coefficient = ecc.taggedHash(TAGS.musig_noncecoef, aggNonce, pubKeyX, msg);
      const aggNonces = [aggNonce.subarray(0, 33), aggNonce.subarray(33)];
      const r = ecc.pointMultiplyAndAddUnsafe(aggNonces[1], coefficient, aggNonces[0], false);
      if (r === null) throw new Error('Unexpected final nonce at infinity');
      const challenge = ecc.secretMod(ecc.taggedHash(TAGS.challenge, ecc.pointX(r), pubKeyX, msg));
      let sPart = ecc.secretMultiply(challenge, cache.tweak);
      if (!ecc.hasEvenY(cache.publicKey)) {
        sPart = ecc.secretNegate(sPart);
      }
      return new ProcessedNonce(r, coefficient, challenge, sPart);
    }
    static load(session) {
      return new ProcessedNonce(
        session.subarray(0, 65),
        session.subarray(65, 97),
        session.subarray(97, 129),
        session.subarray(129)
      );
    }
    dump() {
      const session = new Uint8Array(161);
      session.set(this.finalNonce, 0);
      session.set(this.coefficient, 65);
      session.set(this.challenge, 97);
      session.set(this.sPart, 129);
      return session;
    }
  }
  function normalizeNonceArg(p) {
    if (p === undefined) return [Uint8Array.of(0)];
    return [Uint8Array.of(32), p];
  }
  function partialVerifyInner({ sig, publicKeyX, publicNonces, cache, processedNonce }) {
    const { challenge, coefficient, finalNonce } = processedNonce;
    let rj = ecc.pointMultiplyAndAddUnsafe(publicNonces[1], coefficient, publicNonces[0], false);
    if (rj === null) throw new Error('Unexpected public nonce at infinity');
    if (!ecc.hasEvenY(finalNonce)) rj = ecc.pointNegate(rj);
    let publicKey = ecc.liftX(publicKeyX);
    if (publicKey === null) throw new Error('Invalid verification key');
    if (ecc.hasEvenY(cache.publicKey) === cache.parity) {
      publicKey = ecc.pointNegate(publicKey);
    }
    const ea = ecc.secretMultiply(challenge, cache.coefficient(ecc.pointX(publicKey)));
    const ver = ecc.pointMultiplyAndAddUnsafe(publicKey, ea, rj, true);
    if (ver === null) throw new Error('Unexpected verification point at infinity');
    const sG = ecc.getPublicKey(sig, true);
    if (sG === null) throw new Error('Unexpected signature point at infinity');
    return ver[0] === sG[0] && compare32b(ver.subarray(1), sG.subarray(1)) === 0;
  }
  function partialSignInner({ msg, secretKey, publicKey, secretNonces, cache, processedNonce }) {
    const { challenge, coefficient, finalNonce } = processedNonce;
    const bk2 = ecc.secretMultiply(coefficient, secretNonces[1]);
    let k1bk2 = ecc.secretAdd(secretNonces[0], bk2);
    if (!ecc.hasEvenY(finalNonce)) k1bk2 = ecc.secretNegate(k1bk2);
    if ((ecc.hasEvenY(publicKey) !== cache.parity) !== ecc.hasEvenY(cache.publicKey)) {
      secretKey = ecc.secretNegate(secretKey);
    }
    const ea = ecc.secretMultiply(challenge, cache.coefficient(ecc.pointX(publicKey)));
    const ead = ecc.secretMultiply(ea, secretKey);
    const sig = ecc.secretAdd(ead, k1bk2);
    return sig;
  }
  const pubKeyArgs = ['publicKey', 'publicKeys'];
  const secretArgs = ['tweaks', 'secretKey', 'sig', 'sigs'];
  const otherArgs32b = ['msg', 'base', 'sessionId', 'extraInput'];
  const args32b = [...pubKeyArgs, ...secretArgs, ...otherArgs32b];
  const pubNonceArgs = ['publicNonce', 'publicNonces', 'aggNonce'];
  const otherArgs = ['secretNonce', 'rest', 'signingSession'];
  const argLengths = new Map();
  args32b.forEach((a) => argLengths.set(a, 32));
  pubNonceArgs.forEach((a) => argLengths.set(a, 66));
  argLengths.set('secretNonce', 64);
  argLengths.set('rest', 130);
  argLengths.set('signingSession', 161);
  const secretNames = new Set([...secretArgs, 'secretNonce']);
  function checkArgs(args) {
    for (let [name, values] of Object.entries(args)) {
      if (values === undefined) continue;
      values = Array.isArray(values) ? values : [values];
      if (values.length === 0) throw new TypeError(`0-length ${name}s not supported`);
      for (const value of values) {
        if (value.length !== argLengths.get(name)) throw new TypeError(`Invalid ${name} length`);
        if (!secretNames.has(name)) continue;
        for (let i = 0; i < value.length; i += 32)
          if (!ecc.isSecret(value.subarray(i, i + 32))) throw new TypeError(`Invalid ${name}`);
      }
    }
  }
  function initTweaks(tweaks, tweaksXOnly) {
    checkArgs({ tweaks });
    if (tweaksXOnly === undefined) return new Array(tweaks.length).fill(false);
    if (tweaks.length !== tweaksXOnly.length)
      throw new Error('tweaks and tweaksXOnly have different lengths');
    return tweaksXOnly;
  }
  return {
    keyAgg: (publicKeys, opts = {}) => {
      checkArgs({ publicKeys });
      const cache = KeyAggCache.fromPublicKeys(publicKeys, opts.sort);
      if (opts.tweaks === undefined) return cache.toAggregatePublicKey();
      opts.tweaksXOnly = initTweaks(opts.tweaks, opts.tweaksXOnly);
      return cache.addTweaks(opts.tweaks, opts.tweaksXOnly).toAggregatePublicKey();
    },
    addTweaks: (keyAggSession, tweaks, tweaksXOnly) => {
      checkArgs(keyAggSession);
      tweaksXOnly = initTweaks(tweaks, tweaksXOnly);
      return KeyAggCache.load(keyAggSession).addTweaks(tweaks, tweaksXOnly).toAggregatePublicKey();
    },
    nonceGen: ({ sessionId, secretKey, msg, publicKey, extraInput }) => {
      checkArgs({ sessionId, secretKey, msg, publicKey, extraInput });
      const seed = ecc.taggedHash(
        TAGS.musig_nonce,
        ...[
          sessionId,
          ...normalizeNonceArg(secretKey),
          ...normalizeNonceArg(msg),
          ...normalizeNonceArg(publicKey),
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
        if (pub === null) throw new Error('Secret nonce has no corresponding public nonce');
        publicNonce.set(pub, i * 33);
      }
      return { secretNonce, publicNonce };
    },
    nonceAgg: (publicNonces) => {
      checkArgs({ publicNonces });
      let aggNonces = [publicNonces[0].subarray(0, 33), publicNonces[0].subarray(33)];
      for (let i = 1; i < publicNonces.length; i++) {
        const K1 = ecc.pointAdd(aggNonces[0], publicNonces[i].subarray(0, 33), false);
        const K2 = ecc.pointAdd(aggNonces[1], publicNonces[i].subarray(33), false);
        if (K1 === null || K2 === null) {
          const G = ecc.getPublicKey(U8A1, true);
          aggNonces = [G, G];
          break;
        }
        aggNonces = [K1, K2];
      }
      const aggNonce = new Uint8Array(66);
      aggNonce.set(ecc.pointCompress(aggNonces[0]), 0);
      aggNonce.set(ecc.pointCompress(aggNonces[1]), 33);
      return aggNonce;
    },
    createSigningSession: (aggNonce, msg, keyAggSession) => {
      checkArgs(keyAggSession);
      checkArgs({ aggNonce, msg });
      return ProcessedNonce.process(aggNonce, msg, KeyAggCache.load(keyAggSession)).dump();
    },
    partialSign: ({
      msg,
      secretKey,
      nonce,
      aggNonce,
      keyAggSession,
      signingSession,
      verify = true,
    }) => {
      checkArgs(nonce);
      checkArgs(keyAggSession);
      checkArgs({ msg, secretKey, aggNonce, signingSession });
      const publicKey = ecc.getPublicKey(secretKey, false);
      if (publicKey === null) throw new Error('Invalid secret key, no corresponding public key');
      const secretNonces = [nonce.secretNonce.subarray(0, 32), nonce.secretNonce.subarray(32)];
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
        let publicNonces;
        if (nonce.publicNonce) {
          publicNonces = [nonce.publicNonce.subarray(0, 33), nonce.publicNonce.subarray(33)];
        } else {
          const K1 = ecc.getPublicKey(secretNonces[0], false);
          const K2 = ecc.getPublicKey(secretNonces[1], false);
          if (K1 === null || K2 === null)
            throw new Error('Invalid secret nonce, no corresponding public nonce');
          publicNonces = [K1, K2];
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
    }) => {
      checkArgs(keyAggSession);
      checkArgs({ sig, msg, publicKey, publicNonce, aggNonce, signingSession });
      const publicNonces = [publicNonce.subarray(0, 33), publicNonce.subarray(33)];
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
    signAgg: (sigs, signingSession) => {
      checkArgs({ sigs, signingSession });
      const { finalNonce, sPart } = ProcessedNonce.load(signingSession);
      const aggS = sigs.reduce((a, b) => ecc.secretAdd(a, b), sPart);
      const sig = new Uint8Array(64);
      sig.set(finalNonce.subarray(1, 33), 0);
      sig.set(aggS, 32);
      return sig;
    },
  };
}
exports.MuSigFactory = MuSigFactory;
