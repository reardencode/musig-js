import createHash = require('create-hash');
import * as noble from '@noble/secp256k1';
import * as tiny from 'tiny-secp256k1';
import * as baseCrypto from '../base_crypto';

export const tinyCrypto = {
  ...baseCrypto,
  pointMultiplyUnsafe: tiny.pointMultiply,
  pointMultiplyAndAddUnsafe: (
    p1: Uint8Array,
    a: Uint8Array,
    p2: Uint8Array,
    compress: boolean
  ): Uint8Array | null => {
    const p1a = tiny.pointMultiply(p1, a, false);
    if (p1a === null) return null;
    return tiny.pointAdd(p1a, p2, compress);
  },
  pointAdd: tiny.pointAdd,
  pointAddTweak: tiny.pointAddScalar,
  liftX: (p: Uint8Array): Uint8Array | null => {
    const pC = new Uint8Array(33);
    pC[0] = 2;
    pC.set(p, 1);
    return tiny.pointCompress(pC, false);
  },
  pointCompress: tiny.pointCompress,
  getPublicKey: tiny.pointFromScalar,
  taggedHash: noble.utils.taggedHashSync,
  sha256: (...messages: Uint8Array[]): Uint8Array => {
    const sha256 = createHash('sha256');
    for (const message of messages) sha256.update(message);
    return sha256.digest();
  },
};

noble.utils.sha256Sync = tinyCrypto.sha256;

export const nobleCrypto = {
  ...baseCrypto,
  pointMultiplyUnsafe: (p: Uint8Array, a: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      const product = noble.Point.fromHex(p).multiplyAndAddUnsafe(
        noble.Point.ZERO,
        BigInt(`0x${Buffer.from(a).toString('hex')}`),
        BigInt(1)
      );
      if (!product) return null;
      return product.toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointMultiplyAndAddUnsafe: (
    p1: Uint8Array,
    a: Uint8Array,
    p2: Uint8Array,
    compress: boolean
  ): Uint8Array | null => {
    try {
      const p2p = noble.Point.fromHex(p2);
      const p = noble.Point.fromHex(p1).multiplyAndAddUnsafe(
        p2p,
        BigInt(`0x${Buffer.from(a).toString('hex')}`),
        BigInt(1)
      );
      if (!p) return null;
      return p.toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointAdd: (a: Uint8Array, b: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return noble.Point.fromHex(a).add(noble.Point.fromHex(b)).toRawBytes(compress);
    } catch {
      return null;
    }
  },
  pointAddTweak: (p: Uint8Array, t: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return noble.utils.pointAddScalar(p, t, compress);
    } catch {
      return null;
    }
  },
  liftX: (p: Uint8Array): Uint8Array | null => {
    try {
      return noble.Point.fromHex(p).toRawBytes(false);
    } catch {
      return null;
    }
  },
  pointCompress: (p: Uint8Array, compress: boolean): Uint8Array => {
    return noble.Point.fromHex(p).toRawBytes(compress);
  },
  getPublicKey: (s: Uint8Array, compress: boolean): Uint8Array | null => {
    try {
      return noble.getPublicKey(s, compress);
    } catch {
      return null;
    }
  },
  taggedHash: noble.utils.taggedHashSync,
  sha256: tinyCrypto.sha256,
};
